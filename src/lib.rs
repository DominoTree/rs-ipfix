#[macro_use]
extern crate nom;
extern crate nom_derive;
extern crate serde;

pub mod printer;

pub use printer::*;

use std::{collections::HashMap, net::{Ipv4Addr, Ipv6Addr}};
use nom_derive::{Nom, Parse};
use serde::Serialize;

pub struct IpfixConsumer {
    templates: HashMap<u16, Template>,
    options_templates: HashMap<u16, OptionsTemplate>,
    formatters: ParserMapper,
}

#[allow(dead_code)]
#[derive(Nom, Debug)]
struct IpfixHeader {
    #[nom(Verify="*version == 10")]
    version: u16,
    length: u16,
    export_time: u32,
    sequence_number: u32,
    observation_domain_id: u32,
}

#[allow(dead_code)]
#[derive(Debug)]
struct IpfixMessage<'a> {
    header: IpfixHeader,
    sets: Vec<Set<'a>>,
}

#[derive(Debug)]
pub enum Set<'a> {
    TemplateSet(TemplateSet),
    OptionsTemplateSet(OptionsTemplateSet),
    DataSet(DataSet<'a>),
}

#[derive(Nom, Debug)]
pub struct SetHeader {
    pub set_id: u16, // 2: Template Set, 3: Options Template Set, >255: Data Set
    pub length: u16,
}
#[derive(Debug)]
pub struct TemplateSet {
    #[allow(dead_code)]
    header: SetHeader,
    records: Vec<Template>,
}

#[derive(Nom, Debug)]
struct TemplateHeader {
    template_id: u16,
    field_count: u16,
}
#[derive(Nom, Debug)]
struct Template {
    header: TemplateHeader,
    #[nom(Count="header.field_count")]
    field_specifiers: Vec<FieldSpecifier>,
}

#[derive(Debug)]
pub struct OptionsTemplateSet {
    #[allow(dead_code)]
    header: SetHeader,
    records: Vec<OptionsTemplate>,
}

#[derive(Nom, Debug)]
struct OptionsTemplateHeader {
    id: u16,
    field_count: u16,
    #[allow(dead_code)]
    scope_field_count: u16,
}

#[derive(Nom, Debug)]
struct OptionsTemplate {
    header: OptionsTemplateHeader,
    #[nom(Count="header.field_count")]
    field_specifiers: Vec<FieldSpecifier>,
}

#[derive(Nom, Debug)]
struct FieldSpecifier {
    #[nom(PostExec="let ident = if ident > 32767 { ident - 32768 } else { ident };")]
    ident: u16, // 15b in msg
    field_length: u16,
    #[nom(If="ident > 32767")]
    #[allow(dead_code)]
    enterprise_number: Option<u32>,
}

#[derive(Debug)]
pub struct DataSet<'a> {
    #[allow(dead_code)]
    pub header: SetHeader,
    pub records: Vec<DataRecord<'a>>,
}

#[derive(PartialEq, Debug, Serialize)]
pub struct DataRecord<'a> {
    #[serde(flatten)]
    pub values: HashMap<DataRecordKey<'a>, DataRecordValue<'a>>,
}

#[derive(PartialEq, Eq, Hash, Debug, Serialize)]
#[serde(untagged)]
pub enum DataRecordKey<'a> {
    Str(&'a str),
    U16(u16)
}

#[derive(PartialEq, Debug, Serialize)]
#[serde(untagged)]
pub enum DataRecordValue<'a> {
    IPv4(Ipv4Addr),
    IPv6(Ipv6Addr),
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    String(String),
    Bytes(&'a [u8])
}

impl<'a> DataRecord<'a> {
    // json serialize the DataRecord
    pub fn to_json(&self) -> serde_json::Result<String> {
        Ok(serde_json::to_string(&self)?)
    }
}

impl IpfixConsumer {
    pub fn new() -> IpfixConsumer {
        IpfixConsumer {
            templates: HashMap::new(),
            options_templates: HashMap::new(),
            formatters: get_default_parsers()
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
    pub fn parse_message<'a>(&'a mut self, data: &'a [u8]) -> nom::IResult<&'a [u8], Vec<DataSet>> {
        // this should be 1:1 with UDP datagrams
        // we aren't currently using any of the data from the ipfix message header but we still
        // need to chop it off
        let (bytes, _)= IpfixHeader::parse(data)?;
        let mut remaining_bytes = bytes;
        let mut datasets = Vec::<DataSet>::new();
        
        loop {
            if let Ok((bytes, set_header)) = SetHeader::parse(remaining_bytes) {
                let set_length = (set_header.length - 4) as usize;
                let set_bytes = &bytes[0..set_length];
                
                if bytes.len() - set_length > 0 {
                    remaining_bytes = &bytes[set_length..bytes.len()];
                } else {
                    remaining_bytes = &[];
                }
                
                let set = match set_header.set_id.clone() {
                    2 => Some(parse_template_set(set_bytes, set_header)),
                    3 => Some(parse_options_template_set(set_bytes, set_header)),
                    _ => { // data set
                        if self.templates.contains_key(&set_header.set_id) {
                            let template = self.templates.get(&set_header.set_id).unwrap();
                            Some(parse_data_set(set_bytes, set_header, template, &self.formatters))
                        } else if self.options_templates.contains_key(&set_header.set_id) {
                            let options_template = self.options_templates.get(&set_header.set_id).unwrap();
                            Some(parse_options_set(set_bytes, set_header, options_template, &self.formatters))
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
        
        Ok((remaining_bytes, datasets))
    }
}

#[inline]
fn parse_template_set(input: &[u8], set_header: SetHeader) -> nom::IResult<&[u8], Set> {
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

    named!(parse_many_templates<Vec<Template>>, many0!(complete!(Template::parse)));

    let (rest, templates) = parse_many_templates(input)?;

    let result = Set::TemplateSet(TemplateSet {
        header: set_header,
        records: templates,
    });

    Ok((rest, result))
}

#[inline]
fn parse_options_template_set(input: &[u8], set_header: SetHeader) -> nom::IResult<&[u8], Set> {
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

    named!(parse_many_options_templates<Vec<OptionsTemplate>>, many0!(complete!(OptionsTemplate::parse)));

    let (rest, templates) = parse_many_options_templates(input)?;

    let result = Set::OptionsTemplateSet(OptionsTemplateSet {
        header: set_header,
        records: templates,
    });

    Ok((rest, result))
}

#[inline]
fn parse_data_set<'a>(data: &'a [u8],
                      set_header: SetHeader,
                      template: &Template,
                      formatters: &ParserMapper)
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
        let mut values = HashMap::new();
        for field in &template.field_specifiers {
            let bytes = &data[offset..offset + field.field_length as usize];
            
            if let Some(&(name, formatter)) = formatters.get(&field.ident) {
                let drv = formatter(bytes);
                values.insert(DataRecordKey::Str(name), drv);
            } else {
                values.insert(DataRecordKey::U16(field.ident), DataRecordValue::Bytes(bytes));
            }

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
                         template: &OptionsTemplate,
                         formatters: &ParserMapper)
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
        let mut values = HashMap::new();
        for field in &template.field_specifiers {
            let bytes = &data[offset..offset + field.field_length as usize];

            if let Some(&(name, formatter)) = formatters.get(&field.ident) {
                let drv = formatter(bytes);
                values.insert(DataRecordKey::Str(name), drv);
            } else {
                values.insert(DataRecordKey::U16(field.ident), DataRecordValue::Bytes(bytes));
            }

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
