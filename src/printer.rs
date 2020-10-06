extern crate nom;

use std::collections::HashMap;

use super::conversions;
use super::DataSet;

pub struct IpfixPrinter {
    formatters: HashMap<u16, (&'static str, fn(&[u8]) -> String)>,
}

#[inline]
fn be_int(s: &[u8]) -> String {
    format!("{}",
            match s.len() {
                1 => s[0] as u64,
                2 => conversions::be_buf_to_u16(s) as u64,
                4 => conversions::be_buf_to_u32(s) as u64,
                8 => conversions::be_buf_to_u64(s),
                _ => {
                    println!("TRIED TO CONVERT {} BYTES TO u64", s.len());
                    0 as u64
                }
            })
}

#[inline]
fn ipv4_addr(s: &[u8]) -> String {
    format!(r#""{}.{}.{}.{}""#, s[0], s[1], s[2], s[3])
}

#[inline]
fn ipv6_addr(s: &[u8]) -> String {
    format!(r#""{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}""#,
            s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], s[8], s[9], s[10], s[11], s[12], s[13], s[14], s[15])
}

#[inline]
fn mpls_stack(s: &[u8]) -> String {
    //      0                   1                   2
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                Label                  | Exp |S|
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    // Label:  Label Value, 20 bits
    // Exp:    Experimental Use, 3 bits
    // S:      Bottom of Stack, 1 bit

    named!(parse_mpls_stack <&[u8], (u32, u8, u8)>, bits!(
        tuple!(
            take_bits!( u32, 20 ),
            take_bits!( u8, 3 ),
            take_bits!( u8, 1 )
        )
    ));

    //TODO: do some more conversions here
    if let nom::IResult::Done(_, (label, exp, bottom)) = parse_mpls_stack(s) {
        format!(r#"{{"label":{},"exp":{},"bottom":{}}}"#,
                label,
                exp,
                bottom == 1)
            .into()
    } else {
        println!("{:?}", parse_mpls_stack(s));
        println!("MPLS STACK PARSING FAILED");
        "{}".into()
    }
}

#[macro_export]
macro_rules! field_parser(
    { $($key:expr => ($string:expr, $value:expr)),+ } => {
        {
        let mut m = ::std::collections::HashMap::<u16, (&str, fn(&[u8]) -> String)>::new();
            $(
                m.insert($key, ($string, $value));
            )+
            m
        }
    };
);

impl IpfixPrinter {
    pub fn new() -> IpfixPrinter {
        // TODO: handle non-default settings here
        IpfixPrinter { formatters: IpfixPrinter::get_default_parsers() }
    }

    pub fn print_json(&self, dataset: DataSet) -> Vec<String> {

        let mut strings = Vec::<String>::new();

        for record in dataset.records {
            let mut output = String::new();
            output += "{";

            for (x, data) in record.values {

                if let Some(&(name, formatter)) = self.formatters.get(&x) {
                    output += format!(r#""{}":{},"#, name, formatter(data)).as_str();
                }
            }
            output = String::from(&output[0..output.len() - 1]);
            output += "}";
            strings.push(output);
        }
        strings
    }

    fn get_default_parsers() -> HashMap<u16, (&'static str, fn(&[u8]) -> String)> {
        field_parser!{
            1 => ("octetDeltaCount", be_int),
            2 => ("packetDeltaCount", be_int),
            4 => ("protocolIdentifier", be_int),
            5 => ("classOfServiceIPv4", be_int),
            6 => ("tcpControlBits", be_int),
            7 => ("sourceTransportPort", be_int),
            8 => ("sourceIPv4Address", ipv4_addr),
            9 => ("sourceIPv4Mask", be_int),
            10 => ("ingressInterface", be_int),
            11 => ("destinationTransportPort", be_int),
            12 => ("destinationIPv4Address", ipv4_addr),
            13 => ("destinationIPv4Mask", be_int),
            14 => ("egressInterface", be_int),
            15 => ("ipNextHopIPv4Address", ipv4_addr),
            16 => ("bgpSourceAsNumber", be_int),
            17 => ("bgpDestinationAsNumber", be_int),
            18 => ("bgpNextHopIPv4Address", be_int),
            19 => ("postMCastPacketDeltaCount", be_int),
            20 => ("postMCastOctetDeltaCount", be_int),
            21 => ("flowEndSysUpTime", be_int),
            22 => ("flowStartSysUpTime", be_int),
            23 => ("postOctetDeltaCount", be_int),
            24 => ("postPacketDeltaCount", be_int),
            25 => ("minimumPacketLength", be_int),
            26 => ("maximumPacketLength", be_int),
            27 => ("sourceIPv6Address", ipv6_addr),
            28 => ("destinationIPv6Address", ipv6_addr),
            29 => ("sourceIPv6Mask", be_int),
            30 => ("destinationIPv6Mask", be_int),
            31 => ("flowLabelIPv6", be_int),
            32 => ("icmpTypeCodeIPv4", be_int),
            33 => ("igmpType", be_int),
            36 => ("flowActiveTimeOut", be_int),
            37 => ("flowInactiveTimeout", be_int),
            40 => ("exportedOctetTotalCount", be_int),
            41 => ("exportedMessageTotalCount", be_int),
            42 => ("exportedFlowTotalCount", be_int),
            44 => ("sourceIPv4Prefix", be_int),
            45 => ("destinationIPv4Prefix", be_int),
            46 => ("mplsTopLabelType", be_int),
            47 => ("mplsTopLabelIPv4Address", ipv4_addr),
            52 => ("minimumTtl", be_int),
            53 => ("maximumTtl", be_int),
            54 => ("identificationIPv4", be_int),
            55 => ("postClassOfServiceIPv4", be_int),
            56 => ("sourceMacAddress", be_int),
            57 => ("postDestinationMacAddr", be_int),
            58 => ("vlanId", be_int),
            59 => ("postVlanId", be_int),
            60 => ("ipVersion", be_int),
            62 => ("ipNextHopIPv6Address", ipv6_addr),
            63 => ("bgpNextHopIPv6Address", ipv6_addr),
            64 => ("ipv6ExtensionHeaders", be_int),
            70 => ("mplsTopLabelStackEntry", mpls_stack),
            71 => ("mplsLabelStackEntry2", mpls_stack),
            72 => ("mplsLabelStackEntry3", mpls_stack),
            73 => ("mplsLabelStackEntry4", mpls_stack),
            74 => ("mplsLabelStackEntry5", mpls_stack),
            75 => ("mplsLabelStackEntry6", mpls_stack),
            76 => ("mplsLabelStackEntry7", mpls_stack),
            77 => ("mplsLabelStackEntry8", mpls_stack),
            78 => ("mplsLabelStackEntry9", mpls_stack),
            79 => ("mplsLabelStackEntry10", mpls_stack),
            80 => ("destinationMacAddress", be_int),
            81 => ("postSourceMacAddress", be_int),
            82 => ("interfaceName", be_int),
            83 => ("interfaceDescription", be_int),
            84 => ("samplerName", be_int),
            85 => ("octetTotalCount", be_int),
            86 => ("packetTotalCount", be_int),
            88 => ("fragmentOffsetIPv4", be_int),
            128 => ("bgpNextAdjacentAsNumber", be_int),
            129 => ("bgpPrevAdjacentAsNumber", be_int),
            130 => ("exporterIPv4Address", ipv4_addr),
            131 => ("exporterIPv6Address", ipv6_addr),
            132 => ("droppedOctetDeltaCount", be_int),
            133 => ("droppedPacketDeltaCount", be_int),
            134 => ("droppedOctetTotalCount", be_int),
            135 => ("droppedPacketTotalCount", be_int),
            136 => ("flowEndReason", be_int),
            137 => ("classOfServiceIPv6", be_int),
            138 => ("postClassOfServiceIPv6", be_int),
            139 => ("icmpTypeCodeIPv6", be_int),
            140 => ("mplsTopLabelIPv6Address", ipv6_addr),
            141 => ("lineCardId", be_int),
            142 => ("portId", be_int),
            143 => ("meteringProcessId", be_int),
            144 => ("exportingProcessId", be_int),
            145 => ("templateId", be_int),
            146 => ("wlanChannelId", be_int),
            147 => ("wlanSsid", be_int),
            148 => ("flowId", be_int),
            149 => ("sourceId", be_int),
            150 => ("flowStartSeconds", be_int),
            151 => ("flowEndSeconds", be_int),
            152 => ("flowStartMilliSeconds", be_int),
            153 => ("flowEndMilliSeconds", be_int),
            154 => ("flowStartMicroSeconds", be_int),
            155 => ("flowEndMicroSeconds", be_int),
            156 => ("flowStartNanoSeconds", be_int),
            157 => ("flowEndNanoSeconds", be_int),
            158 => ("flowStartDeltaMicroSeconds", be_int),
            159 => ("flowEndDeltaMicroSeconds", be_int),
            160 => ("systemInitTimeMilliSeconds", be_int),
            161 => ("flowDurationMilliSeconds", be_int),
            162 => ("flowDurationMicroSeconds", be_int),
            163 => ("observedFlowTotalCount", be_int),
            164 => ("ignoredPacketTotalCount", be_int),
            165 => ("ignoredOctetTotalCount", be_int),
            166 => ("notSentFlowTotalCount", be_int),
            167 => ("notSentPacketTotalCount", be_int),
            168 => ("notSentOctetTotalCount", be_int),
            169 => ("destinationIPv6Prefix", be_int),
            170 => ("sourceIPv6Prefix", be_int),
            171 => ("postOctetTotalCount", be_int),
            172 => ("postPacketTotalCount", be_int),
            173 => ("flowKeyIndicator", be_int),
            174 => ("postMCastPacketTotalCount", be_int),
            175 => ("postMCastOctetTotalCount", be_int),
            176 => ("icmpTypeIPv4", be_int),
            177 => ("icmpCodeIPv4", be_int),
            178 => ("icmpTypeIPv6", be_int),
            179 => ("icmpCodeIPv6", be_int),
            180 => ("udpSourcePort", be_int),
            181 => ("udpDestinationPort", be_int),
            182 => ("tcpSourcePort", be_int),
            183 => ("tcpDestinationPort", be_int),
            184 => ("tcpSequenceNumber", be_int),
            185 => ("tcpAcknowledgementNumber", be_int),
            186 => ("tcpWindowSize", be_int),
            187 => ("tcpUrgentPointer", be_int),
            188 => ("tcpHeaderLength", be_int),
            189 => ("ipHeaderLength", be_int),
            190 => ("totalLengthIPv4", be_int),
            191 => ("payloadLengthIPv6", be_int),
            192 => ("ipTimeToLive", be_int),
            193 => ("nextHeaderIPv6", be_int),
            194 => ("ipClassOfService", be_int),
            195 => ("ipDiffServCodePoint", be_int),
            196 => ("ipPrecedence", be_int),
            197 => ("fragmentFlagsIPv4", be_int),
            198 => ("octetDeltaSumOfSquares", be_int),
            199 => ("octetTotalSumOfSquares", be_int),
            200 => ("mplsTopLabelTtl", be_int),
            201 => ("mplsLabelStackLength", be_int),
            202 => ("mplsLabelStackDepth", be_int),
            203 => ("mplsTopLabelExp", be_int),
            204 => ("ipPayloadLength", be_int),
            205 => ("udpMessageLength", be_int),
            206 => ("isMulticast", be_int),
            207 => ("internetHeaderLengthIPv4", be_int),
            208 => ("ipv4Options", be_int),
            209 => ("tcpOptions", be_int),
            210 => ("paddingOctets", be_int),
            213 => ("headerLengthIPv4", be_int),
            214 => ("mplsPayloadLength", be_int)
        }
    }
}
