#[macro_use]
extern crate nom;
extern crate nom_derive;
extern crate serde;

pub mod printer;

use nom::number::complete::be_u8;
pub use printer::*;

use std::{collections::HashMap, net::{Ipv4Addr, Ipv6Addr}};
use nom_derive::{Nom, Parse};
use serde::Serialize;

pub struct IpfixConsumer {
    pub templates: HashMap<u16, Template>,
    pub options_templates: HashMap<u16, OptionsTemplate>,
    pen_formatter: EnterpriseFormatter,
}

#[allow(dead_code)]
#[derive(Nom, Debug)]
pub struct IpfixHeader {
    #[nom(Verify="*version == 10")]
    pub version: u16,
    pub length: u16,
    pub export_time: u32,
    pub sequence_number: u32,
    pub observation_domain_id: u32,
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct IpfixMessage<'a> {
    pub header: IpfixHeader,
    pub sets: Vec<Set<'a>>,
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
    pub header: SetHeader,
    pub records: Vec<Template>,
}

#[derive(Nom, Debug)]
pub struct TemplateHeader {
    pub template_id: u16,
    pub field_count: u16,
}
#[derive(Nom, Debug)]
pub struct Template {
    pub header: TemplateHeader,
    #[nom(Count="header.field_count")]
    pub field_specifiers: Vec<FieldSpecifier>,
}

#[derive(Debug)]
pub struct OptionsTemplateSet {
    #[allow(dead_code)]
    pub header: SetHeader,
    pub records: Vec<OptionsTemplate>,
}

#[derive(Nom, Debug)]
pub struct OptionsTemplateHeader {
    pub id: u16,
    pub field_count: u16,
    #[allow(dead_code)]
    pub scope_field_count: u16,
}

#[derive(Nom, Debug)]
pub struct OptionsTemplate {
    pub header: OptionsTemplateHeader,
    #[nom(Count="header.field_count")]
    pub field_specifiers: Vec<FieldSpecifier>,
}

#[derive(Nom, Debug)]
pub struct FieldSpecifier {
    temp_ident: u16,
    #[nom(Ignore, PostExec="let ident = if temp_ident > 32767 { temp_ident - 32768} else { temp_ident };")]
    pub ident: u16,
    pub field_length: u16,
    #[nom(Cond="temp_ident > 32767")]
    #[allow(dead_code)]
    pub enterprise_number: Option<u32>,

    // to be used to handle the different FS cases
    #[nom(Ignore, PostExec="let is_variable = field_length == 65535;")]
    is_variable: bool,
    #[nom(Ignore, PostExec="let is_pen = enterprise_number.is_some();")]
    is_pen: bool,
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
    Unrecognized(u16),
    Err(String)
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
    Bytes(&'a [u8]),
    MPLS(u32, u8, u8),
    Empty,
}

impl<'a> DataRecord<'a> {
    // json serialize the DataRecord
    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string(&self)
    }
}

impl IpfixConsumer {
    pub fn new() -> IpfixConsumer {

        let mut enterprise_formatters= HashMap::new();
        enterprise_formatters.insert(0, get_default_parsers());
        
        IpfixConsumer {
            templates: HashMap::new(),
            options_templates: HashMap::new(),
            pen_formatter: enterprise_formatters
        }
    }

    pub fn add_custom_field(&mut self, enterprise_number: u32, field_id: u16, name: &'static str, parser: fn (&[u8]) -> DataRecordValue) {
        let m = self.pen_formatter.entry(enterprise_number).or_insert(HashMap::new());
        m.insert(field_id, (name, parser));
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
                
                let set = match set_header.set_id {
                    2 => Some(parse_template_set(set_bytes, set_header)),
                    3 => Some(parse_options_template_set(set_bytes, set_header)),
                    _ => { // data set
                        if self.templates.contains_key(&set_header.set_id) {
                            let template = self.templates.get(&set_header.set_id).unwrap();
                            Some(parse_data_set(set_bytes, set_header, &template.field_specifiers, &self.pen_formatter))
                        } else if self.options_templates.contains_key(&set_header.set_id) {
                            let options_template = self.options_templates.get(&set_header.set_id).unwrap();
                            Some(parse_data_set(set_bytes, set_header, &options_template.field_specifiers, &self.pen_formatter))
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

            if remaining_bytes.is_empty() {
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

// take a field from input, if field_size indicates variable field,
// then take u8 from input and use it as size
fn take_field(input: &[u8], field_size: u16) -> nom::IResult<&[u8], &[u8]> {
    if field_size == 65535 {
        let (rest, actual_size) = call!(input, be_u8)?;
        take!(rest, actual_size)
    } else {
        take!(input, field_size)
    }
}

// based on `takes` which is a vector of tuples (field_id, field_size, enterprise_number) do `take_field`
// returns a hashmap of <field_id, (field_buffer, enterprise_number)>
fn take_fields(input: &[u8], takes: Vec<(u16, u16, u32)>) -> nom::IResult<&[u8], HashMap::<u16, (&[u8], u32)>> {
    
    let mut values = HashMap::<u16, (&[u8], u32)>::new();
    let mut rest = input;
    for (field_ident, field_size, enterprise_number) in takes {
        let (more, field_buf) = take_field(&rest, field_size)?;
        rest = more;
        values.insert(field_ident, (field_buf, enterprise_number));
    }

    Ok((rest, values))
}

// Given DataRecord values (field_id, (field_buffer, enterprise_number)) apply enterprise formatter on it
// returning a datarecord key value map
fn enrich_fields<'a>(values: &HashMap<u16, (&'a [u8], u32)>, enterprise_parsers: &EnterpriseFormatter) -> HashMap<DataRecordKey<'a>, DataRecordValue<'a>> {
    let hs = values.iter()
    .map(|(field_id, (val_bytes, pen))| -> (DataRecordKey, DataRecordValue) {

        
        match enterprise_parsers.get(pen) {
            Some(value_parsers) => {
                match value_parsers.get(field_id) {
                    Some((field_name, field_parser)) => {
                        let parsed_val = field_parser(val_bytes);
                        (DataRecordKey::Str(field_name), parsed_val)
                    },
                    None => {
                        // recognized pen but unrecognized field parser
                        (DataRecordKey::Unrecognized(*field_id), DataRecordValue::Bytes(*val_bytes))
                    }
                }
            },
            None => {
                // unrecognized pen
                (DataRecordKey::Err(format!("unsupported pen {} when trying to parse field {}", pen, field_id)), DataRecordValue::Empty)
            }

        }

    }).collect();

    hs
}


// parse data set based on the field_specifiers provided
// format them with enterprise formatter
fn parse_data_set<'a>(data: &'a [u8],
                      set_header: SetHeader,
                      field_specifiers: &Vec<FieldSpecifier>,
                      formatters: &EnterpriseFormatter)
                      -> nom::IResult<&'a [u8], Set<'a>> {

    let mut temp_buf = data;

    // So a dataset consisit of multiple "records"
    // each records is a bunch of fields, so we need
    // to apply the template on dataset multiple times if required.
    let mut records = Vec::new();
    while temp_buf.len() > 0 {
        // generate a vector of tuples that represent field information to extract
        let takes = field_specifiers.iter().map(|e| (e.ident, e.field_length, e.enterprise_number.unwrap_or(0))).collect::<Vec<(u16, u16, u32)>>();
        // start extracting fields returning a hashmap of field ident to its buffer extracted/sliced
        match take_fields(&temp_buf, takes) {
            Ok((rest, values)) => {
                // update the current buffer and iterate if not empty (indication of more records)
                temp_buf = rest;

                // push the record with enriched fields
                records.push(DataRecord {
                    // TODO : parsing fields doesn't respect PEN
                    values: enrich_fields(&values, formatters)
                });
            },
            Err(_err) => {
                // ???
                break;
            }
        };
    }

    Ok((temp_buf,
        Set::DataSet(DataSet {
            header: set_header,
            records,
        })))
}