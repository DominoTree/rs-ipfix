#[macro_use]
extern crate nom;
extern crate nom_derive;
extern crate serde;
extern crate anyhow;

pub mod printer;

use nom::{error::make_error, number::complete::be_u8};
pub use printer::*;

use std::{collections::HashMap, net::{Ipv4Addr, Ipv6Addr}};
use nom_derive::{Nom, Parse};
use serde::Serialize;
use anyhow::{anyhow, Result};

pub struct IpfixParser {
    pub templates: HashMap<u16, Template>,
    pub options_templates: HashMap<u16, OptionsTemplate>,
    pen_formatter: EnterpriseFormatter,
}

#[allow(dead_code)]
#[derive(Nom, Debug)]
pub struct IpfixMessage<'a> {
    #[nom(Verify="*version == 10")]
    pub version: u16,
    pub length: u16,
    pub export_time: u32,
    pub sequence_number: u32,
    pub observation_domain_id: u32,
    #[nom(Ignore)]
    pub sets: Vec<Set<'a>>
}

#[derive(Debug, PartialEq)]
pub enum SetType {
    DataSet,
    Template,
    OptionTemplate
}

#[derive(Debug)]
pub struct Set<'a> {
    pub hdr: SetHeader,
    pub stype: SetType,
    pub buf: &'a [u8],
    pub data: Vec<DataSet<'a>>,
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

impl OptionsTemplate {
    named!(pub parse_many<Vec<OptionsTemplate>>, many0!(complete!(Self::parse)));
}

impl Template {
    named!(pub parse_many<Vec<Template>>, many0!(complete!(Self::parse)));
}

impl From<u16> for SetType {
    fn from(set_id: u16) -> Self {
        match set_id {
            2 => SetType::Template,
            3 => SetType::OptionTemplate,
            _ => SetType::DataSet
        }
    }
}

impl<'a> DataRecord<'a> {
    // json serialize the DataRecord
    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string(&self)
    }
}

impl<'a> DataSet<'a> {

    // Given DataRecord values (field_id, (field_buffer, enterprise_number)) apply enterprise formatter on it
    // returning a datarecord key value map
    fn enrich_fields(values: &HashMap<u16, (&'a [u8], u32)>, enterprise_parsers: &EnterpriseFormatter) -> HashMap<DataRecordKey<'a>, DataRecordValue<'a>> {
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

    // take a field from input given it's size, and handle variable lengths sec7
    fn take_field(input: &'a [u8], field_size: u16) -> nom::IResult<&'a [u8], &'a [u8]> {
        if field_size == 65535 {
            let (rest, actual_size) = call!(input, be_u8)?;
            take!(rest, actual_size)
        } else {
            take!(input, field_size)
        }
    }

    // based on `takes` which is a vector of tuples (field_id, field_size, enterprise_number) do `take_field`
    // returns a hashmap of <field_id, (field_buffer, enterprise_number)>
    fn take_fields(input: &'a [u8], takes: Vec<(u16, u16, u32)>) -> nom::IResult<&[u8], HashMap::<u16, (&'a [u8], u32)>> {
        
        let mut values = HashMap::<u16, (&[u8], u32)>::new();
        let mut rest = input;
        for (field_ident, field_size, enterprise_number) in takes {
            let (more, field_buf) = Self::take_field(&rest, field_size)?;
            rest = more;
            values.insert(field_ident, (field_buf, enterprise_number));
        }

        Ok((rest, values))
    }

    fn parse(input: &'a [u8], length: u16, set_id: u16, value_parsers: &EnterpriseFormatter, templates: &HashMap<u16, Template>, options_templates: &HashMap<u16, OptionsTemplate>) -> nom::IResult<&'a [u8], DataSet<'a>> {

        let mut temp_buf = input;

        if let Some(template) = templates.get(&set_id) {

            // So a dataset consisit of multiple "records"
            // each records is a bunch of fields, so we need
            // to apply the template on dataset multiple times if required.
            let mut records = Vec::new();
            while !temp_buf.is_empty() {
                // generate a vector of tuples that represent field information to extract
                let takes = template.field_specifiers.iter().map(|e| (e.ident, e.field_length, e.enterprise_number.unwrap_or(0))).collect::<Vec<(u16, u16, u32)>>();
                // start extracting fields returning a hashmap of field ident to its buffer extracted/sliced
                match Self::take_fields(&temp_buf, takes) {
                    Ok((rest, values)) => {
                        // update the current buffer and iterate if not empty (indication of more records)
                        temp_buf = rest;
                        // push the record with enriched fields
                        records.push(DataRecord {
                            // TODO : parsing fields doesn't respect PEN
                            values: Self::enrich_fields(&values, value_parsers)
                        });
                    },
                    Err(_err) => {
                        break;
                    }
                }
            }

            Ok((temp_buf, DataSet {
                header: SetHeader {
                    set_id,
                    length
                },
                records
            }))

        } else if let Some(template) = options_templates.get(&set_id) {

            // So a dataset consisit of multiple "records"
            // each records is a bunch of fields, so we need
            // to apply the template on dataset multiple times if required.
            let mut records = Vec::new();
            while !temp_buf.is_empty() {
                // generate a vector of tuples that represent field information to extract
                let takes = template.field_specifiers.iter().map(|e| (e.ident, e.field_length, e.enterprise_number.unwrap_or(0))).collect::<Vec<(u16, u16, u32)>>();
                // start extracting fields returning a hashmap of field ident to its buffer extracted/sliced
                match Self::take_fields(&temp_buf, takes) {
                    Ok((rest, values)) => {
                        // update the current buffer and iterate if not empty (indication of more records)
                        temp_buf = rest;
                        // push the record with enriched fields
                        records.push(DataRecord {
                            // TODO : parsing fields doesn't respect PEN
                            values: Self::enrich_fields(&values, value_parsers)
                        });
                    },
                    Err(_err) => {
                        break;
                    }
                }
            }

            Ok((temp_buf, DataSet {
                header: SetHeader {
                    set_id,
                    length
                },
                records
            }))

        } else {
            // Happens when no templates for this set_id
            // TODO : proper error
            Err(nom::Err::Incomplete(nom::Needed::Unknown))
        }
    }

}

impl<'a> IpfixMessage<'a> {
    // get the records from the a set of type DataSet
    // if none exists an empty vector is returned.
    pub fn get_dataset_records(&self) -> Vec<&DataRecord> {
        self.sets
        .iter()
        .filter(|set| set.stype == SetType::DataSet)
        .map(|e| &e.data)
        .flatten()
        .map(|e| &e.records)
        .flatten()
        .collect::<Vec<&DataRecord<'_>>>()
    }
}

impl<'a> Set<'a> {

    // TODO : proper errors
    pub fn parse(input: &[u8]) -> nom::IResult<&[u8], Set> {
        let (body, hdr) = SetHeader::parse(input)?;

        if hdr.length < 4 {
            // ???
            return Err(nom::Err::Error(make_error(body, nom::error::ErrorKind::TooLarge)))
        }

        let split_position = (hdr.length - 4) as usize;

        if split_position > body.len() {
            // ???
            return Err(nom::Err::Error(make_error(body, nom::error::ErrorKind::TooLarge)))
        }

        let left_bytes: &[u8] = &body[0..split_position];
        let right_bytes: &[u8] = &body[split_position..];

        Ok((right_bytes, Set {
            stype: hdr.set_id.into(),
            hdr,
            buf: left_bytes,
            data: Vec::new()
        }))
    }

    // extract the sets from body by parsing a set
    // then determining the next one, and parsing them in seq.
    named!(pub parse_many<Vec<Set>>, many0!(complete!(Self::parse)));

    // parse and process the set buffer based on its type
    // and update the respective data structure with the parsed data.
    fn process_set_body(&mut self, fmts: &EnterpriseFormatter, templates: &mut HashMap<u16, Template>, options_templates: &mut HashMap<u16, OptionsTemplate>) -> Result<()> {
        
        match self.stype {
            SetType::DataSet => {
                let (_, ds) = DataSet::parse(self.buf, self.length().unwrap_or(0) as u16,  self.hdr.set_id, fmts, &templates, &options_templates)
                    .map_err(|e| anyhow!("failed parsing dataset : {}", e))?;
                self.data.push(ds);
                Ok(())
            },
            SetType::OptionTemplate => {
                let (_, tv) = OptionsTemplate::parse_many(self.buf)
                    .map_err(|e| anyhow!("failed parsing options templates : {}", e))?;
                for ts in tv {
                    options_templates.insert(ts.header.id, ts);
                };
                Ok(())
            },
            SetType::Template => {
                let (_, tv) = Template::parse_many(self.buf)
                    .map_err(|e| anyhow!("failed parsing templates : {}", e))?;
                for ts in tv {
                    templates.insert(ts.header.template_id, ts);
                }
                Ok(())
            }
        }

    }

    fn length(&self) -> Option<usize> {
        if self.hdr.length < 4 {
            None
        } else {
            Some((self.hdr.length - 4) as usize)
        }
    }
}

impl IpfixParser {

    pub fn new() -> IpfixParser {
        let mut enterprise_formatters= HashMap::new();
        enterprise_formatters.insert(0, get_default_parsers());
        IpfixParser {
            templates: HashMap::new(),
            options_templates: HashMap::new(),
            pen_formatter: enterprise_formatters
        }
    }

    pub fn add_custom_field(&mut self, enterprise_number: u32, field_id: u16, name: &'static str, parser: fn (&[u8]) -> DataRecordValue) {
        let m = self.pen_formatter.entry(enterprise_number).or_insert_with(HashMap::new);
        m.insert(field_id, (name, parser));
    }

    pub fn parse_message<'a>(&'a mut self, input: &'a [u8]) -> Result<IpfixMessage> {
        // this should be 1:1 with UDP datagrams
        // we aren't currently using any of the data from the ipfix message header but we still
        // need to chop it off
        let (body, mut parsed)= IpfixMessage::parse(input)
            .map_err(|e| anyhow!("failed while parsing ipfix header : {:?}", e))?;

        let (_, sets)= Set::parse_many(&body)
            .map_err(|e| anyhow!("failed while extracting sets {:?}", e))?;
        parsed.sets = sets;

        for set in &mut parsed.sets {
            match set.process_set_body(&self.pen_formatter, &mut self.templates, &mut self.options_templates) {
                Ok(()) => {
                },
                Err(_err) => {
                    // TODO : handle
                }
            }
        }

        Ok(parsed)
    }
}