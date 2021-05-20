#[macro_use]
extern crate nom;

pub mod conversions;
pub mod printer;

pub use printer::*;

use conversions::*;
use std::collections::HashMap;

// Using binary trees allows the JSON output to stay in the same order for each record, but its performance is slower than a HashMap.
// Should make functions generic and allow this to be changed by a bool flag.
use std::collections::BTreeMap;

pub struct IpfixConsumer {
    templates: HashMap<u16, Template>,
    options_templates: HashMap<u16, OptionsTemplate>,
}

#[allow(dead_code)]
struct IpfixHeader {
    version: u16,
    length: u16,
    export_time: u32,
    sequence_number: u32,
    observation_domain_id: u32,
}

#[allow(dead_code)]
struct IpfixMessage<'a> {
    header: IpfixHeader,
    sets: Vec<Set<'a>>,
}

pub enum Set<'a> {
    TemplateSet(TemplateSet),
    OptionsTemplateSet(OptionsTemplateSet),
    DataSet(DataSet<'a>),
}

struct SetHeader {
    set_id: u16, // 2: Template Set, 3: Options Template Set, >255: Data Set
    length: u16,
}
pub struct TemplateSet {
    #[allow(dead_code)]
    header: SetHeader,
    records: Vec<Template>,
}

struct TemplateHeader {
    template_id: u16,
    field_count: u16,
}

struct Template {
    header: TemplateHeader,
    field_specifiers: Vec<FieldSpecifier>,
}

pub struct OptionsTemplateSet {
    #[allow(dead_code)]
    header: SetHeader,
    records: Vec<OptionsTemplate>,
}

struct OptionsTemplateHeader {
    id: u16,
    field_count: u16,
    #[allow(dead_code)]
    scope_field_count: u16,
}

struct OptionsTemplate {
    header: OptionsTemplateHeader,
    field_specifiers: Vec<FieldSpecifier>,
}

struct FieldSpecifier {
    ident: u16, // 15b in msg
    field_length: u16,
    #[allow(dead_code)]
    enterprise_number: Option<u32>,
}

pub struct DataSet<'a> {
    #[allow(dead_code)]
    header: SetHeader,
    records: Vec<DataRecord<'a>>,
}

#[derive(PartialEq)]
pub struct DataRecord<'a> {
    values: BTreeMap<u16, &'a [u8]>,
}

impl IpfixConsumer {
    pub fn new() -> IpfixConsumer {
        IpfixConsumer {
            templates: HashMap::new(),
            options_templates: HashMap::new(),
        }
    }

    #[inline]
    fn add_template(&mut self, template: Template) {
        let id = template.header.template_id;
        self.templates.insert(id, template);
    }

    #[inline]
    fn add_options_template(&mut self, template: OptionsTemplate) {
        let id = template.header.id;
        self.options_templates.insert(id, template);
    }

    #[inline]
    pub fn parse_message<'a>(&'a mut self, data: &'a [u8]) -> Result<Vec<DataSet>, &'static str> {
        // this should be 1:1 with UDP datagrams
        // we aren't currently using any of the data from the ipfix message header but we still
        // need to chop it off
        if let Ok((bytes, _)) = parse_ipfix_header(data) {
            let mut remaining_bytes = bytes;
            let mut datasets = Vec::<DataSet>::new();
            loop {
                if let Ok((bytes, set_header)) = parse_set_header(remaining_bytes) {
                    let set_length = (set_header.length - 4) as usize;
                    let set_bytes = &bytes.clone()[0..set_length];
                    if bytes.len() - set_length > 0 {
                        remaining_bytes = &bytes[set_length..bytes.len()];
                    } else {
                        remaining_bytes = &[];
                    }
                    let set = match set_header.set_id.clone() {
                        2 => {
                            // template set
                            Some(parse_template_set(set_bytes, set_header))
                        }
                        3 => {
                            // options template set
                            Some(parse_options_template_set(set_bytes, set_header))
                        }
                        _ => {
                            // data set
                            if self.templates.contains_key(&set_header.set_id) {
                                let template = {
                                    self.templates.get(&set_header.set_id).unwrap()
                                };
                                Some(parse_data_set(set_bytes, set_header, template))
                            } else if self.options_templates.contains_key(&set_header.set_id) {
                                let options_template = {
                                    self.options_templates.get(&set_header.set_id).unwrap()
                                };
                                Some(parse_options_set(set_bytes, set_header, options_template))
                            } else {
                                None
                            }
                        }
                    };
                    if let Some(Ok((_, object))) = set {
                        match object {
                            Set::TemplateSet(set) => {
                                for template in set.records {
                                    self.add_template(template);
                                }
                            }
                            Set::OptionsTemplateSet(set) => {
                                for template in set.records {
                                    self.add_options_template(template);
                                }
                            }
                            Set::DataSet(dataset) => {
                                datasets.push(dataset);
                            }
                        }
                    }
                }
                if remaining_bytes.len() == 0 as usize {
                    break;
                }
            }
            return Ok(datasets);
        }
        Err("Parsing failed")
    }
}

impl<'a> DataRecord<'a> {
    pub fn to_json(&self) {
        for field in &self.values {
            println!("{:?}", field);
        }
    }
}

#[inline]
pub fn is_template_set(data: &[u8]) -> Result<bool, &'static str> {
    // big-endian 0x0f-0x10
    if data.len() >= 18 {
        let id = conversions::be_buf_to_u16(&data[16..18]);
        Ok(id == 2 || id == 3)
    } else {
        Err("Data too short".into())
    }
}

#[inline]
pub fn get_message_length(data: &[u8]) -> Result<u16, &'static str> {
    // big-endian, 0x02-0x03
    if data.len() >= 3 {
        Ok(conversions::be_buf_to_u16(&data[2..4]))
    } else {
        Err("Data too short".into())
    }
}

#[inline]
fn parse_ipfix_header(data: &[u8]) -> nom::IResult<&[u8], IpfixHeader> {
    //  0                   1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |       Version Number          |            Length             |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                           Export Time                         |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                       Sequence Number                         |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                    Observation Domain ID                      |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    named!(ipfix_version <&[u8], u16>, map!(take!(2), be_buf_to_u16));
    named!(message_length <&[u8], u16>, map!(take!(2), be_buf_to_u16));
    named!(export_time <&[u8], u32>, map!(take!(4), be_buf_to_u32));
    named!(sequence_number <&[u8], u32>, map!(take!(4), be_buf_to_u32));
    named!(observation_domain_id <&[u8], u32>, map!(take!(4), be_buf_to_u32));

    named!(ipfix_header <&[u8], IpfixHeader>, do_parse!(
        version: ipfix_version >>
        length: message_length >>
        time: export_time >>
        sequence: sequence_number >>
        domain_id: observation_domain_id >>
        (IpfixHeader {
            version: version,
            length: length,
            export_time: time,
            sequence_number: sequence,
            observation_domain_id: domain_id
        })
    ));

    ipfix_header(&data)
}

#[inline]
fn parse_field_specifier(data: &[u8]) -> nom::IResult<&[u8], FieldSpecifier> {
    // 0                   1                   2                   3
    // 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |E|  Information Element ident. |        Field Length           |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                      Enterprise Number                        |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    // if greater than 2^15, bit is 1, and subtract 2^15 for ident
    named!(element_ident_with_enterprise_bit <&[u8], u16>, map!(take!(2), be_buf_to_u16));
    named!(field_length <&[u8], u16>, map!(take!(2), be_buf_to_u16));
    named!(enterprise_number <&[u8], u32>, map!(take!(4), be_buf_to_u32));

    named!(enterprise_field_specifier<&[u8], (u16, u32)>, tuple!(
        field_length,
        enterprise_number
    ));

    if let Ok((bytes, id)) = element_ident_with_enterprise_bit(data) {
        // pull off the first bit
        if id > 32767 {
            if let Ok((remaining_data, (field_length, enterprise_number))) =
                enterprise_field_specifier(bytes) {
                return Ok((remaining_data,
                        FieldSpecifier {
                            enterprise_number: Some(enterprise_number),
                            ident: id - 32768,
                            field_length: field_length,
                        }));
            }
        } else {
            if let Ok((remaining_data, field_length)) = field_length(bytes) {
                return Ok((remaining_data,
                                          FieldSpecifier {
                                              enterprise_number: None,
                                              ident: id,
                                              field_length: field_length,
                                          }));
            }
        }
    }
    
    Err(nom::Err::Incomplete(nom::Needed::Unknown))
}


#[inline]
fn parse_set_header(data: &[u8]) -> nom::IResult<&[u8], SetHeader> {
    //  0                   1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |          Set ID               |          Length               |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    named!(set_id <&[u8], u16>, map!(take!(2), be_buf_to_u16));
    named!(set_length <&[u8], u16>, map!(take!(2), be_buf_to_u16));

    named!(set_header <&[u8], SetHeader>, do_parse!(
        id: set_id >>
        length: set_length >>
        ( SetHeader {
            set_id: id,
            length: length
        })
    ));

    set_header(data)
}

#[inline]
fn parse_template_header(data: &[u8]) -> nom::IResult<&[u8], TemplateHeader> {
    // 0                   1                   2                   3
    // 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |      Template ID (> 255)      |         Field Count           |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    named!(template_id <&[u8], u16>, map!(take!(2), be_buf_to_u16));
    named!(field_count <&[u8], u16>, map!(take!(2), be_buf_to_u16));

    named!(template_header <&[u8], TemplateHeader>, do_parse!(
        id: template_id >>
        field_count: field_count >>
        ( TemplateHeader {
            template_id: id,
            field_count: field_count
        })
    ));

    template_header(data)
}

#[inline]
fn parse_template_set(mut data: &[u8], set_header: SetHeader) -> nom::IResult<&[u8], Set> {
    //  0                   1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |1| Information Element id. 1.1 |        Field Length 1.1       |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                    Enterprise Number  1.1                     |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |0| Information Element id. 1.2 |        Field Length 1.2       |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |             ...               |              ...              |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |1| Information Element id. 1.N |        Field Length 1.N       |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                    Enterprise Number  1.N                     |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |      Template ID = 257        |         Field Count = M       |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |0| Information Element id. 2.1 |        Field Length 2.1       |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |1| Information Element id. 2.2 |        Field Length 2.2       |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                    Enterprise Number  2.2                     |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |             ...               |              ...              |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |1| Information Element id. 2.M |        Field Length 2.M       |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                    Enterprise Number  2.M                     |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                          Padding (opt)                        |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    let mut templates = Vec::<Template>::new();

    while data.len() > 0 as usize {
        let mut fields = Vec::<FieldSpecifier>::new();
        if let Ok((bytes, header)) = parse_template_header(&data) {
            data = bytes;
            for _ in 0..header.field_count {
                if let Ok((bytes, field)) = parse_field_specifier(data) {
                    fields.push(field);
                    data = bytes;
                }
            }
            templates.push(Template {
                header: header,
                field_specifiers: fields,
            });
        }
    }

    let result = Set::TemplateSet(TemplateSet {
        header: set_header,
        records: templates,
    });

    Ok((data, result))
}

#[inline]
fn parse_options_template_header(data: &[u8]) -> nom::IResult<&[u8], OptionsTemplateHeader> {
    //  0                   1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |         Template ID (> 255)   |         Field Count           |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |      Scope Field Count        |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    named!(template_id <&[u8], u16>, map!(take!(2), be_buf_to_u16));
    named!(field_count <&[u8], u16>, map!(take!(2), be_buf_to_u16));
    named!(scope_field_count <&[u8], u16>, map!(take!(2), be_buf_to_u16));

    named!(options_template_header <&[u8], OptionsTemplateHeader>, do_parse!(
        id: template_id >>
        field_count: field_count >>
        scope_field_count: scope_field_count >>
        (OptionsTemplateHeader {
            id: id,
            field_count: field_count,
            scope_field_count: scope_field_count
        })
    ));

    options_template_header(data)
}

#[inline]
fn parse_options_template_set(mut data: &[u8], set_header: SetHeader) -> nom::IResult<&[u8], Set> {
    //  0                   1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |         <HEADER USE>          |0|  Scope 1 Infor. Element id. |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |     Scope 1 Field Length      |0|  Scope 2 Infor. Element id. |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |     Scope 2 Field Length      |             ...               |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |            ...                |1|  Scope N Infor. Element id. |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |     Scope N Field Length      |   Scope N Enterprise Number  ...
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // ..  Scope N Enterprise Number   |1| Option 1 Infor. Element id. |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |    Option 1 Field Length      |  Option 1 Enterprise Number  ...
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // .. Option 1 Enterprise Number   |              ...              |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |             ...               |0| Option M Infor. Element id. |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |     Option M Field Length     |      Padding (optional)       |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    //    if let nom::IResult::Done(bytes, header) = parse_options_template_header(&data) {

    //TODO: merge this into parse_template_set

    let mut templates = Vec::<OptionsTemplate>::new();

    while data.len() > 0 as usize {
        let mut fields = Vec::<FieldSpecifier>::new();
        if let Ok((bytes, header)) = parse_options_template_header(&data) {
            data = bytes;
            for _ in 0..header.field_count {
                if let Ok((bytes, field)) = parse_field_specifier(data) {
                    fields.push(field);
                    data = bytes;
                }
            }
            templates.push(OptionsTemplate {
                header: header,
                field_specifiers: fields,
            });
        }
    }

    let result = Set::OptionsTemplateSet(OptionsTemplateSet {
        header: set_header,
        records: templates,
    });

    Ok((data, result))
}

#[inline]
fn parse_data_set<'a>(data: &'a [u8],
                      set_header: SetHeader,
                      template: &Template)
                      -> nom::IResult<&'a [u8], Set<'a>> {
    //  0                   1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |   Record 1 - Field Value 1    |   Record 1 - Field Value 2    |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |   Record 1 - Field Value 3    |             ...               |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |   Record 2 - Field Value 1    |   Record 2 - Field Value 2    |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |   Record 2 - Field Value 3    |             ...               |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |   Record 3 - Field Value 1    |   Record 3 - Field Value 2    |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |   Record 3 - Field Value 3    |             ...               |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |              ...              |      Padding (optional)       |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    let mut records = Vec::<DataRecord>::new();
    let mut offset = 0;

    while offset < data.len() {
        let mut values = BTreeMap::<u16, &[u8]>::new();
        for field in &template.field_specifiers {
            let bytes = &data[offset..offset + field.field_length as usize];
            values.insert(field.ident, bytes);
            offset += field.field_length as usize;
        }
        records.push(DataRecord { values: values });
    }

    Ok((data,
        Set::DataSet(DataSet {
            header: set_header,
            records: records,
        })))
}

#[inline]
fn parse_options_set<'a>(data: &'a [u8],
                         set_header: SetHeader,
                         template: &OptionsTemplate)
                         -> nom::IResult<&'a [u8], Set<'a>> {
    //  0                   1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |   Record 1 - Field Value 1    |   Record 1 - Field Value 2    |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |   Record 1 - Field Value 3    |             ...               |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |   Record 2 - Field Value 1    |   Record 2 - Field Value 2    |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |   Record 2 - Field Value 3    |             ...               |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |   Record 3 - Field Value 1    |   Record 3 - Field Value 2    |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |   Record 3 - Field Value 3    |             ...               |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |              ...              |      Padding (optional)       |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    let mut records = Vec::<DataRecord>::new();
    let mut offset = 0;

    while offset < data.len() {
        let mut values = BTreeMap::<u16, &[u8]>::new();
        for field in &template.field_specifiers {
            let bytes = &data[offset..offset + field.field_length as usize];
            values.insert(field.ident, bytes);
            offset += field.field_length as usize;
        }
        records.push(DataRecord { values: values });
    }

    Ok((data,
        Set::DataSet(DataSet {
            header: set_header,
            records: records,
        })))
}
