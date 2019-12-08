use std::collections::HashMap;
use std::convert::{TryFrom, TryInto};
use std::fmt;
use std::net::Ipv4Addr;
use std::num::ParseIntError;
use std::str::FromStr;

use crate::options::{MessageType, OptionCode};

pub const DHCP_COOKIE: [u8; 4] = [99, 130, 83, 99];

type Options = HashMap<OptionCode, Vec<u8>>;

#[derive(PartialEq, Clone, Debug)]
pub struct Packet {
    pub opcode: OpCode,
    pub htype: HardwareType,
    pub hlen: u8,
    pub hops: u8,
    pub xid: u32,
    pub secs: u16,
    pub flags: u16,
    pub ciaddr: Ipv4Addr,
    pub yiaddr: Ipv4Addr,
    pub siaddr: Ipv4Addr,
    pub giaddr: Ipv4Addr,
    pub chaddr: HardwareAddr,
    pub sname: Vec<u8>,
    pub file: Vec<u8>,
    pub cookie: [u8; 4],
    pub options: Options,
}

impl TryFrom<&[u8]> for Packet {
    type Error = String;

    fn try_from(src: &[u8]) -> Result<Self, Self::Error> {
        // Check packet length
        if src.len() < 240 {
            return Err("packet too small".to_owned());
        }

        // Check DHCP cookie value
        if src[236..240] != DHCP_COOKIE {
            return Err("DHCP cookie invalid".to_owned());
        }

        // Check hardware address length
        if src[2] != 6 {
            return Err("hardware addresses must be 6 bytes".to_owned());
        }

        Ok(Packet {
            opcode: OpCode::try_from(src[0]).map_err(|e| e.to_string())?,
            htype: HardwareType::try_from(src[1]).map_err(|e| e.to_string())?,
            hlen: src[2],
            hops: src[3],
            xid: bytes_to_u32(&src[4..8]),
            secs: ((src[8] as u16) << 8) | src[9] as u16,
            flags: ((src[10] as u16) << 8) | src[11] as u16,
            ciaddr: bytes_to_ip_addr(&src[12..16]),
            yiaddr: bytes_to_ip_addr(&src[16..20]),
            siaddr: bytes_to_ip_addr(&src[20..24]),
            giaddr: bytes_to_ip_addr(&src[24..28]),
            chaddr: HardwareAddr::from(&src[28..34]),
            sname: trim_null(&src[44..108]),
            file: trim_null(&src[108..236]),
            cookie: (&src[236..240]).try_into().unwrap(),
            options: Packet::parse_options(src),
        })
    }
}

impl Packet {
    fn parse_options(src: &[u8]) -> Options {
        let mut m = HashMap::new();

        if src.len() <= 240 {
            return m;
        }

        let option_bytes_vec = src[240..].to_vec();
        let mut option_bytes = option_bytes_vec.as_slice();

        while option_bytes.len() >= 2 {
            let code = match OptionCode::try_from(option_bytes[0]) {
                Ok(c) => c,
                _ => break,
            };

            if code == OptionCode::End {
                break;
            }

            if code == OptionCode::Pad {
                option_bytes = &option_bytes[1..];
                continue;
            }

            let size = option_bytes[1] as usize;
            if option_bytes.len() < size + 2 {
                break;
            }

            m.insert(code, option_bytes[2..2 + size].to_vec());
            option_bytes = &option_bytes[2 + size..];
        }

        m
    }

    pub fn broadcast_flag(&self) -> bool {
        (self.flags >> 8) > 127
    }

    pub fn set_broadcast(&mut self, broadcast: bool) {
        if broadcast {
            self.flags = (1 as u16) << 15;
        } else {
            self.flags = 0;
        }
    }

    pub fn message_type(&self) -> Option<MessageType> {
        if let Some(mtype) = self.options.get(&OptionCode::DHCPMessageType) {
            if mtype.is_empty() {
                return None;
            }

            match MessageType::try_from(mtype[0]) {
                Ok(mt) => Some(mt),
                Err(_) => None,
            }
        } else {
            None
        }
    }
}

impl From<&Packet> for Vec<u8> {
    fn from(packet: &Packet) -> Vec<u8> {
        let mut v = vec![0; 240];

        v[0] = packet.opcode as u8;
        v[1] = packet.htype as u8;
        v[2] = packet.hlen as u8;
        // v[3] hops starts at 0
        v[4..8].copy_from_slice(&u32_to_bytes(packet.xid));
        // v[8..10] secs starts at 0, not used
        v[10] = (packet.flags >> 8) as u8;
        v[11] = packet.flags as u8;
        v[12..16].copy_from_slice(&packet.ciaddr.octets());
        v[16..20].copy_from_slice(&packet.yiaddr.octets());
        v[20..24].copy_from_slice(&packet.siaddr.octets());
        v[24..28].copy_from_slice(&packet.giaddr.octets());
        v[28..34].copy_from_slice(&packet.chaddr.octets());

        for (i, b) in packet.sname.iter().take(64).enumerate() {
            v[44 + i] = *b;
        }

        for (i, b) in packet.file.iter().take(128).enumerate() {
            v[108 + i] = *b;
        }

        v[236..240].copy_from_slice(&DHCP_COOKIE);

        v.append(&mut format_options(&packet.options));

        v
    }
}

fn format_options(options: &Options) -> Vec<u8> {
    let mut bytes = Vec::new();

    for (code, value) in options {
        bytes.push(*code as u8);
        bytes.push(value.len() as u8);
        bytes.extend_from_slice(&value);
    }

    bytes
}

fn bytes_to_ip_addr(bytes: &[u8]) -> Ipv4Addr {
    Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3])
}

fn bytes_to_u32(bytes: &[u8]) -> u32 {
    if bytes.len() == 4 {
        ((bytes[0] as u32) << 24)
            | ((bytes[1] as u32) << 16)
            | ((bytes[2] as u32) << 8)
            | bytes[3] as u32
    } else {
        0
    }
}

fn u32_to_bytes(v: u32) -> [u8; 4] {
    [(v >> 24) as u8, (v >> 16) as u8, (v >> 8) as u8, v as u8]
}

fn trim_null(bytes: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();

    for b in bytes.iter().cloned() {
        if b == 0 {
            break;
        }
        v.push(b);
    }

    v
}

#[repr(u8)]
#[derive(PartialEq, Clone, Debug, Copy)]
pub enum OpCode {
    BootRequest = 1,
    BootReply = 2,
}

impl TryFrom<u8> for OpCode {
    type Error = &'static str;

    fn try_from(code: u8) -> Result<Self, Self::Error> {
        match code {
            1 => Ok(OpCode::BootRequest),
            2 => Ok(OpCode::BootReply),
            _ => Err("opcode out of range"),
        }
    }
}

#[repr(u8)]
#[derive(PartialEq, Clone, Debug, Copy)]
pub enum HardwareType {
    Ethernet = 1,
}

impl TryFrom<u8> for HardwareType {
    type Error = &'static str;

    fn try_from(htype: u8) -> Result<Self, Self::Error> {
        match htype {
            1 => Ok(HardwareType::Ethernet),
            _ => Err("hardware type out of range"),
        }
    }
}

#[derive(PartialEq, Clone, Debug, Copy)]
pub struct HardwareAddr([u8; 6]);

impl HardwareAddr {
    /// Get the octets composing the MAC address.
    ///
    /// # Example
    ///
    /// ```
    /// use dhcp_parser::packet::HardwareAddr;
    ///
    /// assert_eq!(
    /// 	"00-14-22-01-23-45".parse::<HardwareAddr>().unwrap().octets(),
    /// 	[0, 20, 34, 1, 35, 69]);
    /// ```
    pub fn octets(self) -> [u8; 6] {
        self.0
    }

    /// Checks if the address is broadcast.
    ///
    /// # Example
    /// ```
    /// use dhcp_parser::packet::HardwareAddr;
    ///
    /// assert!("FF:FF:FF:FF:FF:FF".parse::<HardwareAddr>().unwrap().is_broadcast());
    /// assert!(!"00:00:00:00:00:00".parse::<HardwareAddr>().unwrap().is_broadcast());
    /// ```
    pub fn is_broadcast(self) -> bool {
        self.0 == [0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
    }
}

impl FromStr for HardwareAddr {
    type Err = ParseIntError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let mut result = [0; 6];

        for (i, byte) in value.split(|c| c == ':' || c == '-').enumerate() {
            if i > 5 {
                u8::from_str_radix("error", 10)?;
            }

            result[i] = u8::from_str_radix(byte, 16)?;
        }

        Ok(HardwareAddr(result))
    }
}

impl From<[u8; 6]> for HardwareAddr {
    fn from(value: [u8; 6]) -> HardwareAddr {
        HardwareAddr(value)
    }
}

impl<'a> From<&'a [u8]> for HardwareAddr {
    fn from(value: &'a [u8]) -> HardwareAddr {
        HardwareAddr([value[0], value[1], value[2], value[3], value[4], value[5]])
    }
}

impl fmt::Display for HardwareAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;

    const TEST_MESSAGE: [u8; 240] = [
        1, // op
        1, // htype
        6, // hlen
        0, // hops
        5, 6, 7, 8, // xid
        0, 0, // secs
        11, 12, // flags
        13, 14, 15, 16, // ciaddr
        17, 18, 19, 20, // yiaddr
        21, 22, 23, 24, // siaddr
        25, 26, 27, 28, // giaddr
        0x29, 0x30, 0x31, 0x32, 0x33, 0x34, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // chaddr
        45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67,
        68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90,
        91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107,
        0, // sname: "-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijk",
        109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 109,
        110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 109, 110,
        111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 109, 110, 111,
        112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 109, 110, 111, 112,
        113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 109, 110, 111, 112, 113,
        114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 109, 110, 111, 112, 113, 114,
        115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 109, 0, 0, 0, 0, 0, 0, 0,
        0, // file: "mnopqrstuvwxyz{|}mnopqrstuvwxyz{|}mnopqrstuvwxyz{|}mnopqrstuvwxyz{|}mnopqrstuvwxyz{|}mnopqrstuvwxyz{|}mnopqrstuvwxyz{|}m",
        99, 130, 83, 99, // magic cookie
    ];

    #[test]
    fn test_parse_message() {
        assert_eq!(
            Packet::try_from(TEST_MESSAGE.as_ref()).unwrap(),
            Packet {
                opcode: OpCode::BootRequest,
                htype: HardwareType::Ethernet,
                hlen: 6,
                hops: 0,
                xid: 84281096,
                secs: 0,
                flags: 2828,
                ciaddr: Ipv4Addr::from_str("13.14.15.16").unwrap(),
                yiaddr: Ipv4Addr::from_str("17.18.19.20").unwrap(),
                siaddr: Ipv4Addr::from_str("21.22.23.24").unwrap(),
                giaddr: Ipv4Addr::from_str("25.26.27.28").unwrap(),
                chaddr: HardwareAddr::from_str("29:30:31:32:33:34").unwrap(),
                sname: vec![
                    45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64,
                    65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84,
                    85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103,
                    104, 105, 106, 107,
                ],
                file: vec![
                    109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124,
                    125, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123,
                    124, 125, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122,
                    123, 124, 125, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121,
                    122, 123, 124, 125, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120,
                    121, 122, 123, 124, 125, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119,
                    120, 121, 122, 123, 124, 125, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118,
                    119, 120, 121, 122, 123, 124, 125, 109,
                ],
                cookie: DHCP_COOKIE.clone(),
                options: HashMap::new(),
            }
        );
    }

    #[test]
    fn test_format_message() {
        let p = Packet::try_from(TEST_MESSAGE.as_ref()).unwrap();
        let p_bytes: Vec<u8> = (&p).into();
        assert_eq!(p_bytes, TEST_MESSAGE.as_ref());
    }
}
