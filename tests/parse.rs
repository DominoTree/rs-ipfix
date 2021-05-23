#[cfg(test)]
mod tests {
    extern crate ipfix;

    use self::ipfix::{IpfixConsumer, DataRecordKey, DataRecordValue};
    use std::net::Ipv4Addr;

    #[test]
    fn test_parse() {
        // contains templates 500, 999, 501
        let template_bytes: [u8; 292] =
            [0x00, 0x0A, 0x01, 0x24, 0x58, 0x34, 0x94, 0xCA, 0x08, 0xF3, 0x62, 0x93, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x02, 0x01, 0x14, 0x01, 0xF4, 0x00, 0x1B, 0x00, 0x01, 0x00, 0x08,
             0x00, 0x02, 0x00, 0x08, 0x00, 0x04, 0x00, 0x01, 0x00, 0x05, 0x00, 0x01, 0x00, 0x06,
             0x00, 0x02, 0x00, 0x07, 0x00, 0x02, 0x00, 0x08, 0x00, 0x04, 0x00, 0x09, 0x00, 0x01,
             0x00, 0x0A, 0x00, 0x04, 0x00, 0x0B, 0x00, 0x02, 0x00, 0x0C, 0x00, 0x04, 0x00, 0x0D,
             0x00, 0x01, 0x00, 0x0E, 0x00, 0x04, 0x00, 0x0F, 0x00, 0x04, 0x00, 0x10, 0x00, 0x04,
             0x00, 0x11, 0x00, 0x04, 0x00, 0x20, 0x00, 0x02, 0x00, 0x34, 0x00, 0x01, 0x00, 0x35,
             0x00, 0x01, 0x00, 0x3A, 0x00, 0x02, 0x00, 0x3D, 0x00, 0x01, 0x00, 0x46, 0x00, 0x03,
             0x00, 0x88, 0x00, 0x01, 0x00, 0x98, 0x00, 0x08, 0x00, 0x99, 0x00, 0x08, 0x00, 0xF3,
             0x00, 0x02, 0x00, 0xF5, 0x00, 0x02, 0x03, 0xE7, 0x00, 0x0B, 0x00, 0x01, 0x00, 0x08,
             0x00, 0x02, 0x00, 0x08, 0x00, 0x04, 0x00, 0x01, 0x00, 0x07, 0x00, 0x02, 0x00, 0x08,
             0x00, 0x04, 0x00, 0x0B, 0x00, 0x02, 0x00, 0x0C, 0x00, 0x04, 0x00, 0x20, 0x00, 0x02,
             0x00, 0x3A, 0x00, 0x02, 0x00, 0x98, 0x00, 0x08, 0x00, 0x99, 0x00, 0x08, 0x01, 0xF5,
             0x00, 0x1B, 0x00, 0x01, 0x00, 0x08, 0x00, 0x02, 0x00, 0x08, 0x00, 0x04, 0x00, 0x01,
             0x00, 0x05, 0x00, 0x01, 0x00, 0x06, 0x00, 0x02, 0x00, 0x07, 0x00, 0x02, 0x00, 0x0A,
             0x00, 0x04, 0x00, 0x0B, 0x00, 0x02, 0x00, 0x0E, 0x00, 0x04, 0x00, 0x10, 0x00, 0x04,
             0x00, 0x11, 0x00, 0x04, 0x00, 0x1B, 0x00, 0x10, 0x00, 0x1C, 0x00, 0x10, 0x00, 0x1D,
             0x00, 0x01, 0x00, 0x1E, 0x00, 0x01, 0x00, 0x34, 0x00, 0x01, 0x00, 0x35, 0x00, 0x01,
             0x00, 0x3A, 0x00, 0x02, 0x00, 0x3D, 0x00, 0x01, 0x00, 0x3E, 0x00, 0x10, 0x00, 0x46,
             0x00, 0x03, 0x00, 0x88, 0x00, 0x01, 0x00, 0x8B, 0x00, 0x02, 0x00, 0x98, 0x00, 0x08,
             0x00, 0x99, 0x00, 0x08, 0x00, 0xF3, 0x00, 0x02, 0x00, 0xF5, 0x00, 0x02];

        // contains data sets for templates 999, 500, 999
        let data_bytes: [u8; 1093] =
            [0x00, 0x0A, 0x04, 0x45, 0x58, 0x34, 0x94, 0xCA, 0x08, 0xF3, 0x66, 0x48, 0x00, 0x00,
             0x00, 0x00, 0x03, 0xE7, 0x02, 0x81, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x11,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x11, 0xFC, 0x16, 0xAC, 0x13, 0xDB,
             0x32, 0x00, 0x35, 0xA5, 0x82, 0x01, 0x09, 0x0B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
             0x58, 0x8D, 0x65, 0x0F, 0x78, 0x00, 0x00, 0x01, 0x58, 0x8D, 0x65, 0x0F, 0x78, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x2A, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x0E, 0x06, 0x13, 0xC5, 0xA5, 0x82, 0x48, 0x9A, 0xE6, 0x8E, 0xAC, 0x13, 0xC9, 0xA4,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x58, 0x8D, 0x64, 0xF9, 0x39, 0x00, 0x00,
             0x01, 0x58, 0x8D, 0x65, 0x0F, 0x77, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0A, 0x90,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x06, 0x1B, 0x58, 0x97, 0x8C, 0x56,
             0xF5, 0x93, 0x27, 0x97, 0x8C, 0x05, 0x4D, 0x03, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01,
             0x58, 0x8D, 0x64, 0x7E, 0xBF, 0x00, 0x00, 0x01, 0x58, 0x8D, 0x65, 0x0F, 0x77, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xAC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x04, 0x06, 0x84, 0x79, 0x97, 0x8C, 0x65, 0x89, 0x27, 0x0D, 0x0A, 0x42, 0x22, 0x18,
             0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x58, 0x8D, 0x65, 0x36, 0x0D, 0x00, 0x00,
             0x01, 0x58, 0x8D, 0x65, 0x36, 0x86, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x28,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x06, 0xEC, 0xF7, 0xAC, 0x10, 0x91,
             0x2C, 0x01, 0xBB, 0xA8, 0x3D, 0x95, 0x11, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
             0x58, 0x8D, 0x65, 0x36, 0x86, 0x00, 0x00, 0x01, 0x58, 0x8D, 0x65, 0x36, 0x86, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x6C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x01, 0x11, 0x00, 0x35, 0x97, 0x8C, 0x01, 0x8F, 0xDA, 0x28, 0xAC, 0x1D, 0xEC, 0x52,
             0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x58, 0x8D, 0x65, 0x0F, 0x77, 0x00, 0x00,
             0x01, 0x58, 0x8D, 0x65, 0x0F, 0x77, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x55,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x06, 0x00, 0x50, 0x17, 0x49, 0x02,
             0xDF, 0xB7, 0xEA, 0xCF, 0x0B, 0x01, 0xA2, 0x00, 0x00, 0x02, 0x58, 0x00, 0x00, 0x01,
             0x58, 0x8D, 0x65, 0x0B, 0x46, 0x00, 0x00, 0x01, 0x58, 0x8D, 0x65, 0x0F, 0x77, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x01, 0x06, 0x00, 0x50, 0xCF, 0x0B, 0x1F, 0x7A, 0xA5, 0xF5, 0x68, 0x81, 0xC2, 0x37,
             0x00, 0x00, 0x02, 0x58, 0x00, 0x00, 0x01, 0x58, 0x8D, 0x65, 0x0F, 0x77, 0x00, 0x00,
             0x01, 0x58, 0x8D, 0x65, 0x0F, 0x77, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x0C,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x06, 0xC0, 0x39, 0x97, 0x8C, 0x01,
             0x80, 0xD6, 0x84, 0xAC, 0x15, 0x8D, 0xA3, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
             0x58, 0x8D, 0x65, 0x0D, 0xD2, 0x00, 0x00, 0x01, 0x58, 0x8D, 0x65, 0x0F, 0x78, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xA4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x02, 0x11, 0xC7, 0x6F, 0xAC, 0x1D, 0xED, 0x52, 0x00, 0x35, 0x97, 0x8C, 0x01, 0x8F,
             0x03, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01, 0x58, 0x8D, 0x65, 0x0F, 0x78, 0x00, 0x00,
             0x01, 0x58, 0x8D, 0x65, 0x0F, 0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0xE5,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0D, 0x06, 0x01, 0xBB, 0xC0, 0x7F, 0xE0,
             0x10, 0xC1, 0x33, 0x0A, 0xC1, 0xD6, 0xBB, 0x03, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01,
             0x58, 0x8D, 0x65, 0x33, 0x14, 0x00, 0x00, 0x01, 0x58, 0x8D, 0x65, 0x36, 0x86, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x97, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x03, 0x06, 0x01, 0xBB, 0xD0, 0x59, 0x0C, 0x9D, 0x5F, 0xC2, 0xCF, 0x0B, 0x01, 0xA4,
             0x00, 0x00, 0x02, 0x58, 0x00, 0x00, 0x01, 0x58, 0x8D, 0x65, 0x36, 0x74, 0x00, 0x00,
             0x01, 0x58, 0x8D, 0x65, 0x36, 0x86, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x29,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x06, 0xF7, 0x81, 0x0A, 0x85, 0xF1,
             0x65, 0x01, 0xBD, 0x0A, 0x4A, 0x16, 0x44, 0x03, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01,
             0x58, 0x8D, 0x65, 0x0F, 0x78, 0x00, 0x00, 0x01, 0x58, 0x8D, 0x65, 0x0F, 0x78, 0x01,
             0xF4, 0x00, 0x59, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0xA8, 0x12,
             0x0C, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x0A, 0x9D, 0xE8, 0x1E, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x08, 0x00, 0x3F, 0x3F, 0x02, 0x5C, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
             0x01, 0x58, 0x8D, 0x65, 0x0F, 0x77, 0x00, 0x00, 0x01, 0x58, 0x8D, 0x65, 0x0F, 0x77,
             0x00, 0x00, 0x02, 0x5C, 0x03, 0xE7, 0x01, 0x5B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x06, 0x90, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x06, 0xB3, 0x88, 0xCF,
             0x0B, 0x01, 0xA3, 0x01, 0xBB, 0x0D, 0x5C, 0x1A, 0x3E, 0x03, 0x03, 0x02, 0x7C, 0x00,
             0x00, 0x01, 0x58, 0x8D, 0x65, 0x0F, 0x42, 0x00, 0x00, 0x01, 0x58, 0x8D, 0x65, 0x0F,
             0x77, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x1C, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x04, 0x11, 0xEB, 0x47, 0x97, 0x8C, 0x80, 0x7A, 0x00, 0x35, 0xA5, 0x82,
             0x01, 0x09, 0x03, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01, 0x58, 0x8D, 0x65, 0x0F, 0x78,
             0x00, 0x00, 0x01, 0x58, 0x8D, 0x65, 0x0F, 0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x6D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x06, 0x0D, 0x3D, 0xA5,
             0x82, 0xDD, 0x0A, 0xFA, 0x50, 0x97, 0x8C, 0x72, 0x8B, 0x0B, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x01, 0x58, 0x8D, 0x65, 0x0F, 0x78, 0x00, 0x00, 0x01, 0x58, 0x8D, 0x65, 0x0F,
             0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xFE, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x08, 0x06, 0x01, 0xBB, 0xA5, 0x82, 0xE6, 0xE6, 0xE1, 0x93, 0xAA, 0x08,
             0xAA, 0x53, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x58, 0x8D, 0x65, 0x0F, 0x78,
             0x00, 0x00, 0x01, 0x58, 0x8D, 0x65, 0x0F, 0x79, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x8E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x11, 0x41, 0x71, 0xAC,
             0x1D, 0xED, 0x52, 0x00, 0x35, 0x97, 0x8C, 0x01, 0x8F, 0x08, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x01, 0x58, 0x8D, 0x65, 0x0F, 0x78, 0x00, 0x00, 0x01, 0x58, 0x8D, 0x65, 0x0F,
             0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0xF7, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x0B, 0x06, 0xCC, 0x12, 0xAC, 0x13, 0xBE, 0x95, 0x01, 0xBB, 0xC7, 0x5B,
             0x8B, 0xC8, 0x00, 0x00, 0x02, 0x58, 0x00, 0x00, 0x01, 0x58, 0x8D, 0x65, 0x0E, 0x7D,
             0x00, 0x00, 0x01, 0x58, 0x8D, 0x65, 0x0F, 0x77, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x4D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x11, 0xB8, 0x78, 0x97,
             0x8C, 0x42, 0xA3, 0x00, 0x35, 0xAC, 0x18, 0x8F, 0x2A, 0x08, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x01, 0x58, 0x8D, 0x65, 0x0F, 0x78, 0x00, 0x00, 0x01, 0x58, 0x8D, 0x65, 0x0F,
             0x78];

        let mut parser = IpfixConsumer::new();
        
        assert!(parser.parse_message(&template_bytes).is_ok());
        
        let (_, datasets) = parser.parse_message(&data_bytes).unwrap();
        for dataset in &datasets {
            for datarecord in &dataset.records {
                let json = datarecord.to_json().unwrap();
                println!("{:?}", json);
            }
        }
        assert!(datasets.len() == 3);
        let d0 = &datasets[0];
        assert!(d0.header.set_id == 999);
        assert!(d0.header.length == 641);
        assert!(d0.records.len() == 13);
        let d0r0 = &d0.records[0];
        assert!(d0r0.values.len() == 11);
        let d0r0v = &d0r0.values;
        
        assert!(d0r0v.get(&DataRecordKey::Str("sourceIPv4Address")).unwrap() == &DataRecordValue::IPv4(Ipv4Addr::new(172, 19, 219, 50)));
        assert!(d0r0v.get(&DataRecordKey::Str("flowEndMilliSeconds")).unwrap() == &DataRecordValue::U64(1479840960376));
        assert!(d0r0v.get(&DataRecordKey::Str("destinationTransportPort")).unwrap() == &DataRecordValue::U16(53));
        assert!(d0r0v.get(&DataRecordKey::Str("protocolIdentifier")).unwrap() == &DataRecordValue::U8(17));
    }
    // nprobe -i ens160 -V10 -n localhost:1337 -T "@NTOPNG@" 
    #[test]
    fn test_parse_template_enterprise_fields() {
        // 257, 258, 259, 260
        let temp_1 = [0x00, 0x0a, 0x03, 0xd4, 0x60, 0xa7, 0x9f, 0xe8, 0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0xc8, 0x00, 0x02, 0x03, 0xc4, 0x01, 0x01, 0x00, 0x26,  0x00, 0x01, 0x00, 0x08, 0x00, 0x02, 0x00, 0x04, 0x00, 0x04, 0x00, 0x01,  0x00, 0x05, 0x00, 0x01, 0x00, 0x07, 0x00, 0x02, 0x00, 0x08, 0x00, 0x04,  0x00, 0x0a, 0x00, 0x04, 0x00, 0x0b, 0x00, 0x02, 0x00, 0x0c, 0x00, 0x04,  0x00, 0x0e, 0x00, 0x04, 0x00, 0x15, 0x00, 0x04, 0x00, 0x16, 0x00, 0x04,  0x00, 0x17, 0x00, 0x08, 0x00, 0x18, 0x00, 0x04, 0x00, 0x37, 0x00, 0x01,  0x00, 0x3a, 0x00, 0x02, 0x00, 0x38, 0x00, 0x06, 0x00, 0x39, 0x00, 0x06,  0x00, 0x3c, 0x00, 0x01, 0x00, 0x82, 0x00, 0x04, 0x80, 0x50, 0x00, 0x02,  0x00, 0x00, 0x8b, 0x30, 0x80, 0x51, 0x00, 0x02, 0x00, 0x00, 0x8b, 0x30,  0x80, 0x7b, 0x00, 0x04, 0x00, 0x00, 0x8b, 0x30, 0x80, 0x7c, 0x00, 0x04,  0x00, 0x00, 0x8b, 0x30, 0x80, 0x4e, 0x00, 0x01, 0x00, 0x00, 0x8b, 0x30,  0x80, 0x4f, 0x00, 0x01, 0x00, 0x00, 0x8b, 0x30, 0x80, 0x7d, 0x00, 0x04,  0x00, 0x00, 0x8b, 0x30, 0x80, 0x6d, 0x00, 0x04, 0x00, 0x00, 0x8b, 0x30,  0x80, 0x6e, 0x00, 0x04, 0x00, 0x00, 0x8b, 0x30, 0x80, 0x6f, 0x00, 0x04,  0x00, 0x00, 0x8b, 0x30, 0x80, 0x70, 0x00, 0x04, 0x00, 0x00, 0x8b, 0x30,  0x80, 0x76, 0x00, 0x02, 0x00, 0x00, 0x8b, 0x30, 0x80, 0xbc, 0xff, 0xff,  0x00, 0x00, 0x8b, 0x30, 0x80, 0xbd, 0xff, 0xff, 0x00, 0x00, 0x8b, 0x30,  0x81, 0xa0, 0x00, 0x02, 0x00, 0x00, 0x8b, 0x30, 0x81, 0xa4, 0x00, 0x02,  0x00, 0x00, 0x8b, 0x30, 0x81, 0xfd, 0x00, 0x04, 0x00, 0x00, 0x8b, 0x30,  0x82, 0x0f, 0x00, 0x02, 0x00, 0x00, 0x8b, 0x30, 0x01, 0x02, 0x00, 0x26,  0x00, 0x01, 0x00, 0x08, 0x00, 0x02, 0x00, 0x04, 0x00, 0x04, 0x00, 0x01,  0x00, 0x05, 0x00, 0x01, 0x00, 0x07, 0x00, 0x02, 0x00, 0x0a, 0x00, 0x04,  0x00, 0x0b, 0x00, 0x02, 0x00, 0x0e, 0x00, 0x04, 0x00, 0x15, 0x00, 0x04,  0x00, 0x16, 0x00, 0x04, 0x00, 0x17, 0x00, 0x08, 0x00, 0x18, 0x00, 0x04,  0x00, 0x1b, 0x00, 0x10, 0x00, 0x1c, 0x00, 0x10, 0x00, 0x37, 0x00, 0x01,  0x00, 0x3a, 0x00, 0x02, 0x00, 0x38, 0x00, 0x06, 0x00, 0x39, 0x00, 0x06,  0x00, 0x3c, 0x00, 0x01, 0x00, 0x83, 0x00, 0x10, 0x80, 0x50, 0x00, 0x02,  0x00, 0x00, 0x8b, 0x30, 0x80, 0x51, 0x00, 0x02, 0x00, 0x00, 0x8b, 0x30,  0x80, 0x7b, 0x00, 0x04, 0x00, 0x00, 0x8b, 0x30, 0x80, 0x7c, 0x00, 0x04,  0x00, 0x00, 0x8b, 0x30, 0x80, 0x4e, 0x00, 0x01, 0x00, 0x00, 0x8b, 0x30,  0x80, 0x4f, 0x00, 0x01, 0x00, 0x00, 0x8b, 0x30, 0x80, 0x7d, 0x00, 0x04,  0x00, 0x00, 0x8b, 0x30, 0x80, 0x6d, 0x00, 0x04, 0x00, 0x00, 0x8b, 0x30,  0x80, 0x6e, 0x00, 0x04, 0x00, 0x00, 0x8b, 0x30, 0x80, 0x6f, 0x00, 0x04,  0x00, 0x00, 0x8b, 0x30, 0x80, 0x70, 0x00, 0x04, 0x00, 0x00, 0x8b, 0x30,  0x80, 0x76, 0x00, 0x02, 0x00, 0x00, 0x8b, 0x30, 0x80, 0xbc, 0xff, 0xff,  0x00, 0x00, 0x8b, 0x30, 0x80, 0xbd, 0xff, 0xff, 0x00, 0x00, 0x8b, 0x30,  0x81, 0xa0, 0x00, 0x02, 0x00, 0x00, 0x8b, 0x30, 0x81, 0xa4, 0x00, 0x02,  0x00, 0x00, 0x8b, 0x30, 0x81, 0xfd, 0x00, 0x04, 0x00, 0x00, 0x8b, 0x30,  0x82, 0x0f, 0x00, 0x02, 0x00, 0x00, 0x8b, 0x30, 0x01, 0x03, 0x00, 0x29,  0x00, 0x01, 0x00, 0x08, 0x00, 0x02, 0x00, 0x04, 0x00, 0x04, 0x00, 0x01,  0x00, 0x05, 0x00, 0x01, 0x00, 0x07, 0x00, 0x02, 0x00, 0x08, 0x00, 0x04,  0x00, 0x0a, 0x00, 0x04, 0x00, 0x0b, 0x00, 0x02, 0x00, 0x0c, 0x00, 0x04,  0x00, 0x0e, 0x00, 0x04, 0x00, 0x15, 0x00, 0x04, 0x00, 0x16, 0x00, 0x04,  0x00, 0x17, 0x00, 0x08, 0x00, 0x18, 0x00, 0x04, 0x00, 0x37, 0x00, 0x01,  0x00, 0x3a, 0x00, 0x02, 0x00, 0x38, 0x00, 0x06, 0x00, 0x39, 0x00, 0x06,  0x00, 0x3c, 0x00, 0x01, 0x00, 0x82, 0x00, 0x04, 0x80, 0x50, 0x00, 0x02,  0x00, 0x00, 0x8b, 0x30, 0x80, 0x51, 0x00, 0x02, 0x00, 0x00, 0x8b, 0x30,  0x80, 0x7b, 0x00, 0x04, 0x00, 0x00, 0x8b, 0x30, 0x80, 0x7c, 0x00, 0x04,  0x00, 0x00, 0x8b, 0x30, 0x80, 0x4e, 0x00, 0x01, 0x00, 0x00, 0x8b, 0x30,  0x80, 0x4f, 0x00, 0x01, 0x00, 0x00, 0x8b, 0x30, 0x80, 0x7d, 0x00, 0x04,  0x00, 0x00, 0x8b, 0x30, 0x80, 0x6d, 0x00, 0x04, 0x00, 0x00, 0x8b, 0x30,  0x80, 0x6e, 0x00, 0x04, 0x00, 0x00, 0x8b, 0x30, 0x80, 0x6f, 0x00, 0x04,  0x00, 0x00, 0x8b, 0x30, 0x80, 0x70, 0x00, 0x04, 0x00, 0x00, 0x8b, 0x30,  0x80, 0x76, 0x00, 0x02, 0x00, 0x00, 0x8b, 0x30, 0x80, 0xbc, 0xff, 0xff,  0x00, 0x00, 0x8b, 0x30, 0x80, 0xbd, 0xff, 0xff, 0x00, 0x00, 0x8b, 0x30,  0x81, 0xa0, 0x00, 0x02, 0x00, 0x00, 0x8b, 0x30, 0x81, 0xa4, 0x00, 0x02,  0x00, 0x00, 0x8b, 0x30, 0x81, 0xfd, 0x00, 0x04, 0x00, 0x00, 0x8b, 0x30,  0x82, 0x0f, 0x00, 0x02, 0x00, 0x00, 0x8b, 0x30, 0x80, 0xcd, 0xff, 0xff,  0x00, 0x00, 0x8b, 0x30, 0x80, 0xcf, 0x00, 0x01, 0x00, 0x00, 0x8b, 0x30,  0x80, 0xd0, 0x00, 0x01, 0x00, 0x00, 0x8b, 0x30, 0x01, 0x04, 0x00, 0x29,  0x00, 0x01, 0x00, 0x08, 0x00, 0x02, 0x00, 0x04, 0x00, 0x04, 0x00, 0x01,  0x00, 0x05, 0x00, 0x01, 0x00, 0x07, 0x00, 0x02, 0x00, 0x0a, 0x00, 0x04,  0x00, 0x0b, 0x00, 0x02, 0x00, 0x0e, 0x00, 0x04, 0x00, 0x15, 0x00, 0x04,  0x00, 0x16, 0x00, 0x04, 0x00, 0x17, 0x00, 0x08, 0x00, 0x18, 0x00, 0x04,  0x00, 0x1b, 0x00, 0x10, 0x00, 0x1c, 0x00, 0x10, 0x00, 0x37, 0x00, 0x01,  0x00, 0x3a, 0x00, 0x02, 0x00, 0x38, 0x00, 0x06, 0x00, 0x39, 0x00, 0x06,  0x00, 0x3c, 0x00, 0x01, 0x00, 0x83, 0x00, 0x10, 0x80, 0x50, 0x00, 0x02,  0x00, 0x00, 0x8b, 0x30, 0x80, 0x51, 0x00, 0x02, 0x00, 0x00, 0x8b, 0x30,  0x80, 0x7b, 0x00, 0x04, 0x00, 0x00, 0x8b, 0x30, 0x80, 0x7c, 0x00, 0x04,  0x00, 0x00, 0x8b, 0x30, 0x80, 0x4e, 0x00, 0x01, 0x00, 0x00, 0x8b, 0x30,  0x80, 0x4f, 0x00, 0x01, 0x00, 0x00, 0x8b, 0x30, 0x80, 0x7d, 0x00, 0x04,  0x00, 0x00, 0x8b, 0x30, 0x80, 0x6d, 0x00, 0x04, 0x00, 0x00, 0x8b, 0x30,  0x80, 0x6e, 0x00, 0x04, 0x00, 0x00, 0x8b, 0x30, 0x80, 0x6f, 0x00, 0x04,  0x00, 0x00, 0x8b, 0x30, 0x80, 0x70, 0x00, 0x04, 0x00, 0x00, 0x8b, 0x30,  0x80, 0x76, 0x00, 0x02, 0x00, 0x00, 0x8b, 0x30, 0x80, 0xbc, 0xff, 0xff,  0x00, 0x00, 0x8b, 0x30, 0x80, 0xbd, 0xff, 0xff, 0x00, 0x00, 0x8b, 0x30,  0x81, 0xa0, 0x00, 0x02, 0x00, 0x00, 0x8b, 0x30, 0x81, 0xa4, 0x00, 0x02,  0x00, 0x00, 0x8b, 0x30, 0x81, 0xfd, 0x00, 0x04, 0x00, 0x00, 0x8b, 0x30,  0x82, 0x0f, 0x00, 0x02, 0x00, 0x00, 0x8b, 0x30, 0x80, 0xcd, 0xff, 0xff,  0x00, 0x00, 0x8b, 0x30, 0x80, 0xcf, 0x00, 0x01, 0x00, 0x00, 0x8b, 0x30,  0x80, 0xd0, 0x00, 0x01, 0x00, 0x00, 0x8b, 0x30];
        // 261, 262
        let temp_2 = [0x00, 0x0a, 0x02, 0x1c, 0x60, 0xa7, 0x9f, 0xe8, 0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0xc8, 0x00, 0x02, 0x02, 0x0c, 0x01, 0x05, 0x00, 0x2a,  0x00, 0x01, 0x00, 0x08, 0x00, 0x02, 0x00, 0x04, 0x00, 0x04, 0x00, 0x01,  0x00, 0x05, 0x00, 0x01, 0x00, 0x07, 0x00, 0x02, 0x00, 0x08, 0x00, 0x04,  0x00, 0x0a, 0x00, 0x04, 0x00, 0x0b, 0x00, 0x02, 0x00, 0x0c, 0x00, 0x04,  0x00, 0x0e, 0x00, 0x04, 0x00, 0x15, 0x00, 0x04, 0x00, 0x16, 0x00, 0x04,  0x00, 0x17, 0x00, 0x08, 0x00, 0x18, 0x00, 0x04, 0x00, 0x37, 0x00, 0x01,  0x00, 0x3a, 0x00, 0x02, 0x00, 0x38, 0x00, 0x06, 0x00, 0x39, 0x00, 0x06,  0x00, 0x3c, 0x00, 0x01, 0x00, 0x82, 0x00, 0x04, 0x80, 0x50, 0x00, 0x02,  0x00, 0x00, 0x8b, 0x30, 0x80, 0x51, 0x00, 0x02, 0x00, 0x00, 0x8b, 0x30,  0x80, 0x7b, 0x00, 0x04, 0x00, 0x00, 0x8b, 0x30, 0x80, 0x7c, 0x00, 0x04,  0x00, 0x00, 0x8b, 0x30, 0x80, 0x4e, 0x00, 0x01, 0x00, 0x00, 0x8b, 0x30,  0x80, 0x4f, 0x00, 0x01, 0x00, 0x00, 0x8b, 0x30, 0x80, 0x7d, 0x00, 0x04,  0x00, 0x00, 0x8b, 0x30, 0x80, 0x6d, 0x00, 0x04, 0x00, 0x00, 0x8b, 0x30,  0x80, 0x6e, 0x00, 0x04, 0x00, 0x00, 0x8b, 0x30, 0x80, 0x6f, 0x00, 0x04,  0x00, 0x00, 0x8b, 0x30, 0x80, 0x70, 0x00, 0x04, 0x00, 0x00, 0x8b, 0x30,  0x80, 0x76, 0x00, 0x02, 0x00, 0x00, 0x8b, 0x30, 0x80, 0xbc, 0xff, 0xff,  0x00, 0x00, 0x8b, 0x30, 0x80, 0xbd, 0xff, 0xff, 0x00, 0x00, 0x8b, 0x30,  0x81, 0xa0, 0x00, 0x02, 0x00, 0x00, 0x8b, 0x30, 0x81, 0xa4, 0x00, 0x02,  0x00, 0x00, 0x8b, 0x30, 0x81, 0xfd, 0x00, 0x04, 0x00, 0x00, 0x8b, 0x30,  0x82, 0x0f, 0x00, 0x02, 0x00, 0x00, 0x8b, 0x30, 0x80, 0xb4, 0xff, 0xff,  0x00, 0x00, 0x8b, 0x30, 0x81, 0x68, 0xff, 0xff, 0x00, 0x00, 0x8b, 0x30,  0x80, 0xb5, 0x00, 0x02, 0x00, 0x00, 0x8b, 0x30, 0x81, 0x69, 0xff, 0xff,  0x00, 0x00, 0x8b, 0x30, 0x01, 0x06, 0x00, 0x2a, 0x00, 0x01, 0x00, 0x08,  0x00, 0x02, 0x00, 0x04, 0x00, 0x04, 0x00, 0x01, 0x00, 0x05, 0x00, 0x01,  0x00, 0x07, 0x00, 0x02, 0x00, 0x0a, 0x00, 0x04, 0x00, 0x0b, 0x00, 0x02,  0x00, 0x0e, 0x00, 0x04, 0x00, 0x15, 0x00, 0x04, 0x00, 0x16, 0x00, 0x04,  0x00, 0x17, 0x00, 0x08, 0x00, 0x18, 0x00, 0x04, 0x00, 0x1b, 0x00, 0x10,  0x00, 0x1c, 0x00, 0x10, 0x00, 0x37, 0x00, 0x01, 0x00, 0x3a, 0x00, 0x02,  0x00, 0x38, 0x00, 0x06, 0x00, 0x39, 0x00, 0x06, 0x00, 0x3c, 0x00, 0x01,  0x00, 0x83, 0x00, 0x10, 0x80, 0x50, 0x00, 0x02, 0x00, 0x00, 0x8b, 0x30,  0x80, 0x51, 0x00, 0x02, 0x00, 0x00, 0x8b, 0x30, 0x80, 0x7b, 0x00, 0x04,  0x00, 0x00, 0x8b, 0x30, 0x80, 0x7c, 0x00, 0x04, 0x00, 0x00, 0x8b, 0x30,  0x80, 0x4e, 0x00, 0x01, 0x00, 0x00, 0x8b, 0x30, 0x80, 0x4f, 0x00, 0x01,  0x00, 0x00, 0x8b, 0x30, 0x80, 0x7d, 0x00, 0x04, 0x00, 0x00, 0x8b, 0x30,  0x80, 0x6d, 0x00, 0x04, 0x00, 0x00, 0x8b, 0x30, 0x80, 0x6e, 0x00, 0x04,  0x00, 0x00, 0x8b, 0x30, 0x80, 0x6f, 0x00, 0x04, 0x00, 0x00, 0x8b, 0x30,  0x80, 0x70, 0x00, 0x04, 0x00, 0x00, 0x8b, 0x30, 0x80, 0x76, 0x00, 0x02,  0x00, 0x00, 0x8b, 0x30, 0x80, 0xbc, 0xff, 0xff, 0x00, 0x00, 0x8b, 0x30,  0x80, 0xbd, 0xff, 0xff, 0x00, 0x00, 0x8b, 0x30, 0x81, 0xa0, 0x00, 0x02,  0x00, 0x00, 0x8b, 0x30, 0x81, 0xa4, 0x00, 0x02, 0x00, 0x00, 0x8b, 0x30,  0x81, 0xfd, 0x00, 0x04, 0x00, 0x00, 0x8b, 0x30, 0x82, 0x0f, 0x00, 0x02,  0x00, 0x00, 0x8b, 0x30, 0x80, 0xb4, 0xff, 0xff, 0x00, 0x00, 0x8b, 0x30,  0x81, 0x68, 0xff, 0xff, 0x00, 0x00, 0x8b, 0x30, 0x80, 0xb5, 0x00, 0x02,  0x00, 0x00, 0x8b, 0x30, 0x81, 0x69, 0xff, 0xff, 0x00, 0x00, 0x8b, 0x30];
        let mut parser = IpfixConsumer::new();
        let _ = parser.parse_message(&temp_1);
        let _ = parser.parse_message(&temp_2);
        // sum the number of parsed enterprise fields
        let mut enterprise_fields = 0;
        for (_k, v) in &parser.templates {
            for fs in &v.field_specifiers {
                println!("{:?}", fs);
                enterprise_fields += if fs.enterprise_number.is_some() { 1 } else { 0 };
            }
        }
    
        assert!(enterprise_fields == 122);
    }

    // nprobe -i ens160 -V10 -n localhost:1337 -T "@NTOPNG@" 
    #[test]
    fn test_parse_data_variable_fields() {
        // 257, 258, 259, 260
        let temp_1 = [0x00, 0x0a, 0x03, 0xd4, 0x60, 0xa7, 0x9f, 0xe8, 0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0xc8, 0x00, 0x02, 0x03, 0xc4, 0x01, 0x01, 0x00, 0x26,  0x00, 0x01, 0x00, 0x08, 0x00, 0x02, 0x00, 0x04, 0x00, 0x04, 0x00, 0x01,  0x00, 0x05, 0x00, 0x01, 0x00, 0x07, 0x00, 0x02, 0x00, 0x08, 0x00, 0x04,  0x00, 0x0a, 0x00, 0x04, 0x00, 0x0b, 0x00, 0x02, 0x00, 0x0c, 0x00, 0x04,  0x00, 0x0e, 0x00, 0x04, 0x00, 0x15, 0x00, 0x04, 0x00, 0x16, 0x00, 0x04,  0x00, 0x17, 0x00, 0x08, 0x00, 0x18, 0x00, 0x04, 0x00, 0x37, 0x00, 0x01,  0x00, 0x3a, 0x00, 0x02, 0x00, 0x38, 0x00, 0x06, 0x00, 0x39, 0x00, 0x06,  0x00, 0x3c, 0x00, 0x01, 0x00, 0x82, 0x00, 0x04, 0x80, 0x50, 0x00, 0x02,  0x00, 0x00, 0x8b, 0x30, 0x80, 0x51, 0x00, 0x02, 0x00, 0x00, 0x8b, 0x30,  0x80, 0x7b, 0x00, 0x04, 0x00, 0x00, 0x8b, 0x30, 0x80, 0x7c, 0x00, 0x04,  0x00, 0x00, 0x8b, 0x30, 0x80, 0x4e, 0x00, 0x01, 0x00, 0x00, 0x8b, 0x30,  0x80, 0x4f, 0x00, 0x01, 0x00, 0x00, 0x8b, 0x30, 0x80, 0x7d, 0x00, 0x04,  0x00, 0x00, 0x8b, 0x30, 0x80, 0x6d, 0x00, 0x04, 0x00, 0x00, 0x8b, 0x30,  0x80, 0x6e, 0x00, 0x04, 0x00, 0x00, 0x8b, 0x30, 0x80, 0x6f, 0x00, 0x04,  0x00, 0x00, 0x8b, 0x30, 0x80, 0x70, 0x00, 0x04, 0x00, 0x00, 0x8b, 0x30,  0x80, 0x76, 0x00, 0x02, 0x00, 0x00, 0x8b, 0x30, 0x80, 0xbc, 0xff, 0xff,  0x00, 0x00, 0x8b, 0x30, 0x80, 0xbd, 0xff, 0xff, 0x00, 0x00, 0x8b, 0x30,  0x81, 0xa0, 0x00, 0x02, 0x00, 0x00, 0x8b, 0x30, 0x81, 0xa4, 0x00, 0x02,  0x00, 0x00, 0x8b, 0x30, 0x81, 0xfd, 0x00, 0x04, 0x00, 0x00, 0x8b, 0x30,  0x82, 0x0f, 0x00, 0x02, 0x00, 0x00, 0x8b, 0x30, 0x01, 0x02, 0x00, 0x26,  0x00, 0x01, 0x00, 0x08, 0x00, 0x02, 0x00, 0x04, 0x00, 0x04, 0x00, 0x01,  0x00, 0x05, 0x00, 0x01, 0x00, 0x07, 0x00, 0x02, 0x00, 0x0a, 0x00, 0x04,  0x00, 0x0b, 0x00, 0x02, 0x00, 0x0e, 0x00, 0x04, 0x00, 0x15, 0x00, 0x04,  0x00, 0x16, 0x00, 0x04, 0x00, 0x17, 0x00, 0x08, 0x00, 0x18, 0x00, 0x04,  0x00, 0x1b, 0x00, 0x10, 0x00, 0x1c, 0x00, 0x10, 0x00, 0x37, 0x00, 0x01,  0x00, 0x3a, 0x00, 0x02, 0x00, 0x38, 0x00, 0x06, 0x00, 0x39, 0x00, 0x06,  0x00, 0x3c, 0x00, 0x01, 0x00, 0x83, 0x00, 0x10, 0x80, 0x50, 0x00, 0x02,  0x00, 0x00, 0x8b, 0x30, 0x80, 0x51, 0x00, 0x02, 0x00, 0x00, 0x8b, 0x30,  0x80, 0x7b, 0x00, 0x04, 0x00, 0x00, 0x8b, 0x30, 0x80, 0x7c, 0x00, 0x04,  0x00, 0x00, 0x8b, 0x30, 0x80, 0x4e, 0x00, 0x01, 0x00, 0x00, 0x8b, 0x30,  0x80, 0x4f, 0x00, 0x01, 0x00, 0x00, 0x8b, 0x30, 0x80, 0x7d, 0x00, 0x04,  0x00, 0x00, 0x8b, 0x30, 0x80, 0x6d, 0x00, 0x04, 0x00, 0x00, 0x8b, 0x30,  0x80, 0x6e, 0x00, 0x04, 0x00, 0x00, 0x8b, 0x30, 0x80, 0x6f, 0x00, 0x04,  0x00, 0x00, 0x8b, 0x30, 0x80, 0x70, 0x00, 0x04, 0x00, 0x00, 0x8b, 0x30,  0x80, 0x76, 0x00, 0x02, 0x00, 0x00, 0x8b, 0x30, 0x80, 0xbc, 0xff, 0xff,  0x00, 0x00, 0x8b, 0x30, 0x80, 0xbd, 0xff, 0xff, 0x00, 0x00, 0x8b, 0x30,  0x81, 0xa0, 0x00, 0x02, 0x00, 0x00, 0x8b, 0x30, 0x81, 0xa4, 0x00, 0x02,  0x00, 0x00, 0x8b, 0x30, 0x81, 0xfd, 0x00, 0x04, 0x00, 0x00, 0x8b, 0x30,  0x82, 0x0f, 0x00, 0x02, 0x00, 0x00, 0x8b, 0x30, 0x01, 0x03, 0x00, 0x29,  0x00, 0x01, 0x00, 0x08, 0x00, 0x02, 0x00, 0x04, 0x00, 0x04, 0x00, 0x01,  0x00, 0x05, 0x00, 0x01, 0x00, 0x07, 0x00, 0x02, 0x00, 0x08, 0x00, 0x04,  0x00, 0x0a, 0x00, 0x04, 0x00, 0x0b, 0x00, 0x02, 0x00, 0x0c, 0x00, 0x04,  0x00, 0x0e, 0x00, 0x04, 0x00, 0x15, 0x00, 0x04, 0x00, 0x16, 0x00, 0x04,  0x00, 0x17, 0x00, 0x08, 0x00, 0x18, 0x00, 0x04, 0x00, 0x37, 0x00, 0x01,  0x00, 0x3a, 0x00, 0x02, 0x00, 0x38, 0x00, 0x06, 0x00, 0x39, 0x00, 0x06,  0x00, 0x3c, 0x00, 0x01, 0x00, 0x82, 0x00, 0x04, 0x80, 0x50, 0x00, 0x02,  0x00, 0x00, 0x8b, 0x30, 0x80, 0x51, 0x00, 0x02, 0x00, 0x00, 0x8b, 0x30,  0x80, 0x7b, 0x00, 0x04, 0x00, 0x00, 0x8b, 0x30, 0x80, 0x7c, 0x00, 0x04,  0x00, 0x00, 0x8b, 0x30, 0x80, 0x4e, 0x00, 0x01, 0x00, 0x00, 0x8b, 0x30,  0x80, 0x4f, 0x00, 0x01, 0x00, 0x00, 0x8b, 0x30, 0x80, 0x7d, 0x00, 0x04,  0x00, 0x00, 0x8b, 0x30, 0x80, 0x6d, 0x00, 0x04, 0x00, 0x00, 0x8b, 0x30,  0x80, 0x6e, 0x00, 0x04, 0x00, 0x00, 0x8b, 0x30, 0x80, 0x6f, 0x00, 0x04,  0x00, 0x00, 0x8b, 0x30, 0x80, 0x70, 0x00, 0x04, 0x00, 0x00, 0x8b, 0x30,  0x80, 0x76, 0x00, 0x02, 0x00, 0x00, 0x8b, 0x30, 0x80, 0xbc, 0xff, 0xff,  0x00, 0x00, 0x8b, 0x30, 0x80, 0xbd, 0xff, 0xff, 0x00, 0x00, 0x8b, 0x30,  0x81, 0xa0, 0x00, 0x02, 0x00, 0x00, 0x8b, 0x30, 0x81, 0xa4, 0x00, 0x02,  0x00, 0x00, 0x8b, 0x30, 0x81, 0xfd, 0x00, 0x04, 0x00, 0x00, 0x8b, 0x30,  0x82, 0x0f, 0x00, 0x02, 0x00, 0x00, 0x8b, 0x30, 0x80, 0xcd, 0xff, 0xff,  0x00, 0x00, 0x8b, 0x30, 0x80, 0xcf, 0x00, 0x01, 0x00, 0x00, 0x8b, 0x30,  0x80, 0xd0, 0x00, 0x01, 0x00, 0x00, 0x8b, 0x30, 0x01, 0x04, 0x00, 0x29,  0x00, 0x01, 0x00, 0x08, 0x00, 0x02, 0x00, 0x04, 0x00, 0x04, 0x00, 0x01,  0x00, 0x05, 0x00, 0x01, 0x00, 0x07, 0x00, 0x02, 0x00, 0x0a, 0x00, 0x04,  0x00, 0x0b, 0x00, 0x02, 0x00, 0x0e, 0x00, 0x04, 0x00, 0x15, 0x00, 0x04,  0x00, 0x16, 0x00, 0x04, 0x00, 0x17, 0x00, 0x08, 0x00, 0x18, 0x00, 0x04,  0x00, 0x1b, 0x00, 0x10, 0x00, 0x1c, 0x00, 0x10, 0x00, 0x37, 0x00, 0x01,  0x00, 0x3a, 0x00, 0x02, 0x00, 0x38, 0x00, 0x06, 0x00, 0x39, 0x00, 0x06,  0x00, 0x3c, 0x00, 0x01, 0x00, 0x83, 0x00, 0x10, 0x80, 0x50, 0x00, 0x02,  0x00, 0x00, 0x8b, 0x30, 0x80, 0x51, 0x00, 0x02, 0x00, 0x00, 0x8b, 0x30,  0x80, 0x7b, 0x00, 0x04, 0x00, 0x00, 0x8b, 0x30, 0x80, 0x7c, 0x00, 0x04,  0x00, 0x00, 0x8b, 0x30, 0x80, 0x4e, 0x00, 0x01, 0x00, 0x00, 0x8b, 0x30,  0x80, 0x4f, 0x00, 0x01, 0x00, 0x00, 0x8b, 0x30, 0x80, 0x7d, 0x00, 0x04,  0x00, 0x00, 0x8b, 0x30, 0x80, 0x6d, 0x00, 0x04, 0x00, 0x00, 0x8b, 0x30,  0x80, 0x6e, 0x00, 0x04, 0x00, 0x00, 0x8b, 0x30, 0x80, 0x6f, 0x00, 0x04,  0x00, 0x00, 0x8b, 0x30, 0x80, 0x70, 0x00, 0x04, 0x00, 0x00, 0x8b, 0x30,  0x80, 0x76, 0x00, 0x02, 0x00, 0x00, 0x8b, 0x30, 0x80, 0xbc, 0xff, 0xff,  0x00, 0x00, 0x8b, 0x30, 0x80, 0xbd, 0xff, 0xff, 0x00, 0x00, 0x8b, 0x30,  0x81, 0xa0, 0x00, 0x02, 0x00, 0x00, 0x8b, 0x30, 0x81, 0xa4, 0x00, 0x02,  0x00, 0x00, 0x8b, 0x30, 0x81, 0xfd, 0x00, 0x04, 0x00, 0x00, 0x8b, 0x30,  0x82, 0x0f, 0x00, 0x02, 0x00, 0x00, 0x8b, 0x30, 0x80, 0xcd, 0xff, 0xff,  0x00, 0x00, 0x8b, 0x30, 0x80, 0xcf, 0x00, 0x01, 0x00, 0x00, 0x8b, 0x30,  0x80, 0xd0, 0x00, 0x01, 0x00, 0x00, 0x8b, 0x30];
        // 261, 262
        let temp_2 = [0x00, 0x0a, 0x02, 0x1c, 0x60, 0xa7, 0x9f, 0xe8, 0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0xc8, 0x00, 0x02, 0x02, 0x0c, 0x01, 0x05, 0x00, 0x2a,  0x00, 0x01, 0x00, 0x08, 0x00, 0x02, 0x00, 0x04, 0x00, 0x04, 0x00, 0x01,  0x00, 0x05, 0x00, 0x01, 0x00, 0x07, 0x00, 0x02, 0x00, 0x08, 0x00, 0x04,  0x00, 0x0a, 0x00, 0x04, 0x00, 0x0b, 0x00, 0x02, 0x00, 0x0c, 0x00, 0x04,  0x00, 0x0e, 0x00, 0x04, 0x00, 0x15, 0x00, 0x04, 0x00, 0x16, 0x00, 0x04,  0x00, 0x17, 0x00, 0x08, 0x00, 0x18, 0x00, 0x04, 0x00, 0x37, 0x00, 0x01,  0x00, 0x3a, 0x00, 0x02, 0x00, 0x38, 0x00, 0x06, 0x00, 0x39, 0x00, 0x06,  0x00, 0x3c, 0x00, 0x01, 0x00, 0x82, 0x00, 0x04, 0x80, 0x50, 0x00, 0x02,  0x00, 0x00, 0x8b, 0x30, 0x80, 0x51, 0x00, 0x02, 0x00, 0x00, 0x8b, 0x30,  0x80, 0x7b, 0x00, 0x04, 0x00, 0x00, 0x8b, 0x30, 0x80, 0x7c, 0x00, 0x04,  0x00, 0x00, 0x8b, 0x30, 0x80, 0x4e, 0x00, 0x01, 0x00, 0x00, 0x8b, 0x30,  0x80, 0x4f, 0x00, 0x01, 0x00, 0x00, 0x8b, 0x30, 0x80, 0x7d, 0x00, 0x04,  0x00, 0x00, 0x8b, 0x30, 0x80, 0x6d, 0x00, 0x04, 0x00, 0x00, 0x8b, 0x30,  0x80, 0x6e, 0x00, 0x04, 0x00, 0x00, 0x8b, 0x30, 0x80, 0x6f, 0x00, 0x04,  0x00, 0x00, 0x8b, 0x30, 0x80, 0x70, 0x00, 0x04, 0x00, 0x00, 0x8b, 0x30,  0x80, 0x76, 0x00, 0x02, 0x00, 0x00, 0x8b, 0x30, 0x80, 0xbc, 0xff, 0xff,  0x00, 0x00, 0x8b, 0x30, 0x80, 0xbd, 0xff, 0xff, 0x00, 0x00, 0x8b, 0x30,  0x81, 0xa0, 0x00, 0x02, 0x00, 0x00, 0x8b, 0x30, 0x81, 0xa4, 0x00, 0x02,  0x00, 0x00, 0x8b, 0x30, 0x81, 0xfd, 0x00, 0x04, 0x00, 0x00, 0x8b, 0x30,  0x82, 0x0f, 0x00, 0x02, 0x00, 0x00, 0x8b, 0x30, 0x80, 0xb4, 0xff, 0xff,  0x00, 0x00, 0x8b, 0x30, 0x81, 0x68, 0xff, 0xff, 0x00, 0x00, 0x8b, 0x30,  0x80, 0xb5, 0x00, 0x02, 0x00, 0x00, 0x8b, 0x30, 0x81, 0x69, 0xff, 0xff,  0x00, 0x00, 0x8b, 0x30, 0x01, 0x06, 0x00, 0x2a, 0x00, 0x01, 0x00, 0x08,  0x00, 0x02, 0x00, 0x04, 0x00, 0x04, 0x00, 0x01, 0x00, 0x05, 0x00, 0x01,  0x00, 0x07, 0x00, 0x02, 0x00, 0x0a, 0x00, 0x04, 0x00, 0x0b, 0x00, 0x02,  0x00, 0x0e, 0x00, 0x04, 0x00, 0x15, 0x00, 0x04, 0x00, 0x16, 0x00, 0x04,  0x00, 0x17, 0x00, 0x08, 0x00, 0x18, 0x00, 0x04, 0x00, 0x1b, 0x00, 0x10,  0x00, 0x1c, 0x00, 0x10, 0x00, 0x37, 0x00, 0x01, 0x00, 0x3a, 0x00, 0x02,  0x00, 0x38, 0x00, 0x06, 0x00, 0x39, 0x00, 0x06, 0x00, 0x3c, 0x00, 0x01,  0x00, 0x83, 0x00, 0x10, 0x80, 0x50, 0x00, 0x02, 0x00, 0x00, 0x8b, 0x30,  0x80, 0x51, 0x00, 0x02, 0x00, 0x00, 0x8b, 0x30, 0x80, 0x7b, 0x00, 0x04,  0x00, 0x00, 0x8b, 0x30, 0x80, 0x7c, 0x00, 0x04, 0x00, 0x00, 0x8b, 0x30,  0x80, 0x4e, 0x00, 0x01, 0x00, 0x00, 0x8b, 0x30, 0x80, 0x4f, 0x00, 0x01,  0x00, 0x00, 0x8b, 0x30, 0x80, 0x7d, 0x00, 0x04, 0x00, 0x00, 0x8b, 0x30,  0x80, 0x6d, 0x00, 0x04, 0x00, 0x00, 0x8b, 0x30, 0x80, 0x6e, 0x00, 0x04,  0x00, 0x00, 0x8b, 0x30, 0x80, 0x6f, 0x00, 0x04, 0x00, 0x00, 0x8b, 0x30,  0x80, 0x70, 0x00, 0x04, 0x00, 0x00, 0x8b, 0x30, 0x80, 0x76, 0x00, 0x02,  0x00, 0x00, 0x8b, 0x30, 0x80, 0xbc, 0xff, 0xff, 0x00, 0x00, 0x8b, 0x30,  0x80, 0xbd, 0xff, 0xff, 0x00, 0x00, 0x8b, 0x30, 0x81, 0xa0, 0x00, 0x02,  0x00, 0x00, 0x8b, 0x30, 0x81, 0xa4, 0x00, 0x02, 0x00, 0x00, 0x8b, 0x30,  0x81, 0xfd, 0x00, 0x04, 0x00, 0x00, 0x8b, 0x30, 0x82, 0x0f, 0x00, 0x02,  0x00, 0x00, 0x8b, 0x30, 0x80, 0xb4, 0xff, 0xff, 0x00, 0x00, 0x8b, 0x30,  0x81, 0x68, 0xff, 0xff, 0x00, 0x00, 0x8b, 0x30, 0x80, 0xb5, 0x00, 0x02,  0x00, 0x00, 0x8b, 0x30, 0x81, 0x69, 0xff, 0xff, 0x00, 0x00, 0x8b, 0x30];
        
        // dns sample
        let d1 = [0x00, 0x0a, 0x00, 0xb8, 0x60, 0xa7, 0xa0, 0xc8, 0x00, 0x00, 0x00, 0x03,  0x00, 0x00, 0x00, 0xad, 0x01, 0x03, 0x00, 0xa8, 0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x53, 0x00, 0x00, 0x00, 0x01, 0x11, 0x00, 0xd5, 0xff,  0xc0, 0xa8, 0x64, 0x49, 0x00, 0x00, 0x00, 0x00, 0x00, 0x35, 0xc0, 0xa8,  0x64, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x22, 0x11, 0x00, 0x00,  0x21, 0x8e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x68, 0x00, 0x00,  0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x29, 0x10, 0x6f, 0x2e, 0x78,  0xd7, 0x52, 0x0f, 0x6b, 0xe7, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x82, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x25, 0x61,  0x73, 0x69, 0x6d, 0x6f, 0x76, 0x2e, 0x76, 0x6f, 0x72, 0x74, 0x65, 0x78,  0x2e, 0x64, 0x61, 0x74, 0x61, 0x2e, 0x74, 0x72, 0x61, 0x66, 0x66, 0x69,  0x63, 0x6d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x72, 0x2e, 0x6e, 0x65, 0x74,  0x1c, 0x00, 0x00, 0x00];
        // http sample
        let d2 = [0x00, 0x0a, 0x00, 0xb0, 0x60, 0xa7, 0xa0, 0xc8, 0x00, 0x00, 0x00, 0x04,  0x00, 0x00, 0x00, 0xad, 0x01, 0x05, 0x00, 0xa0, 0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x01, 0xbf, 0x00, 0x00, 0x00, 0x07, 0x06, 0x00, 0xd3, 0x20,  0xc0, 0xa8, 0x64, 0x49, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x5d, 0xb8,  0xd8, 0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x24, 0x5c, 0x00, 0x00,  0x22, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x53, 0x00, 0x00,  0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x29, 0x10, 0x6f, 0x2e, 0x78,  0xd7, 0x52, 0x0f, 0x6b, 0xe7, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x63, 0x00, 0x00,  0x00, 0x00, 0x00, 0xc6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00,  0xfa, 0xf0, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x65,  0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x03,  0x47, 0x45, 0x54, 0x00, 0xc8, 0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c,  0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x00];

        let mut parser = IpfixConsumer::new();

        // add custom fields for ntop pen
        parser.add_custom_field(35632, 205, "DNS_QUERY", ipfix::be_string);
        parser.add_custom_field(35632, 206, "DNS_QUERY_ID", ipfix::be_string);
        parser.add_custom_field(35632, 207, "DNS_QUERY_TYPE", ipfix::be_string);
        parser.add_custom_field(35632, 208, "DNS_RET_CODE", ipfix::be_string);
        parser.add_custom_field(35632, 209, "DNS_NUM_ANSWERS", ipfix::be_string);
        parser.add_custom_field(35632, 352, "DNS_TTL_ANSWER", ipfix::be_string);
        parser.add_custom_field(35632, 398, "DNS_RESPONSE", ipfix::be_string);
        parser.add_custom_field(35632, 180, "HTTP_URL", ipfix::be_string);
        parser.add_custom_field(35632, 360, "HTTP_METHOD", ipfix::be_string);
        parser.add_custom_field(35632, 181, "HTTP_RET_CODE", ipfix::be_string);
        parser.add_custom_field(35632, 182, "HTTP_REFERER", ipfix::be_string);
        parser.add_custom_field(35632, 183, "HTTP_UA", ipfix::be_string);
        parser.add_custom_field(35632, 184, "HTTP_MIME", ipfix::be_string);
        parser.add_custom_field(35632, 187, "HTTP_HOST", ipfix::be_string);
        parser.add_custom_field(35632, 361, "HTTP_SITE", ipfix::be_string);
        parser.add_custom_field(35632, 460, "HTTP_X_FORWARDED_FOR", ipfix::be_string);
        parser.add_custom_field(35632, 461, "HTTP_VIA", ipfix::be_string);
        parser.add_custom_field(35632, 81, "DST_FRAGMENTS", ipfix::be_string);
        parser.add_custom_field(35632, 123, "CLIENT_NW_LATENCY_MS", ipfix::be_string);
        parser.add_custom_field(35632, 124, "SERVER_NW_LATENCY_MS", ipfix::be_string);
        parser.add_custom_field(35632, 79, "SERVER_TCP_FLAGS", ipfix::be_string);
        parser.add_custom_field(35632, 110, "RETRANSMITTED_OUT_PKTS", ipfix::be_string);
        parser.add_custom_field(35632, 111, "OOORDER_IN_PKTS", ipfix::be_string);
        parser.add_custom_field(35632, 188, "TLS_SERVER_NAME", ipfix::be_string);
        parser.add_custom_field(35632, 189, "BITTORRENT_HASH", ipfix::be_string);
        parser.add_custom_field(35632, 416, "TCP_WIN_MAX_IN", ipfix::be_string);
        parser.add_custom_field(35632, 80, "SRC_FRAGMENTS", ipfix::be_string);
        parser.add_custom_field(35632, 78, "CLIENT_TCP_FLAGS", ipfix::be_string);
        parser.add_custom_field(35632, 125, "APPL_LATENCY_MS", ipfix::be_string);
        parser.add_custom_field(35632, 109, "RETRANSMITTED_IN_PKTS", ipfix::be_string);
        parser.add_custom_field(35632, 420, "TCP_WIN_MAX_OUT", ipfix::be_string);
        parser.add_custom_field(35632, 509, "L7_PROTO_RISK", ipfix::be_string);
        parser.add_custom_field(35632, 527, "L7_RISK_SCORE", ipfix::be_string);
        parser.add_custom_field(35632, 278, "GTPV2_APN_NAME", ipfix::be_string);
        parser.add_custom_field(35632, 280, "GTPV2_ULI_MNC", ipfix::be_string);
        parser.add_custom_field(35632, 180, "HTTP_URL", ipfix::be_string);
        parser.add_custom_field(35632, 380, "RTP_RTT", ipfix::be_string);
        parser.add_custom_field(35632, 112, "OOORDER_OUT_PKTS", ipfix::be_string);
        parser.add_custom_field(35632, 118, "L7_PROTO", ipfix::be_string);
        
        let _ = parser.parse_message(&temp_1);
        let _ = parser.parse_message(&temp_2);

        let (dns_rest, dns) = parser.parse_message(&d1).unwrap();
        // consumed fully
        assert!(dns_rest.is_empty());
    
        // the custom field dns query for ntop en 35632 is parsed
        if let DataRecordValue::String(query) = dns[0].records[0].values.get(&DataRecordKey::Str("DNS_QUERY")).unwrap() {
            assert!(query == "asimov.vortex.data.trafficmanager.net");
        }

        let (http_rest, http) = parser.parse_message(&d2).unwrap();
        // consumed fully
        assert!(http_rest.is_empty());
        if let DataRecordValue::String(site) = http[0].records[0].values.get(&DataRecordKey::Str("HTTP_SITE")).unwrap() {
            assert!(site == "example.com");
        }
    }
}
