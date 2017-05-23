use std::io;
use byteorder::ReadBytesExt;
use byteorder::NetworkEndian;

use tcp::TcpHeader;
use tcp::parse_tcp_header;

pub fn parse_ip_header<'a>(buf: &'a [u8]) -> io::Result<(IpHeader, &'a [u8])> {
    let mut cursor = io::Cursor::new(buf);

    let (version, header_len) = {
        let byte = cursor.read_u8()?;
        (byte >> 4, byte & 0xf)
    };

    assert_eq!(version, 4);
    assert_eq!(header_len * 4, 20);

    let tos = cursor.read_u8()?;
    let total_len = cursor.read_u16::<NetworkEndian>()?;

    assert_eq!(total_len as usize, buf.len());

    let id = cursor.read_u16::<NetworkEndian>()?;
    let (flags, fragment_offset) = {
        let short = cursor.read_u16::<NetworkEndian>()?;
        ((short >> 13) as u8, short & 0x1fff)
    };

    let ttl = cursor.read_u8()?;
    let protocol = cursor.read_u8()?;
    let checksum = cursor.read_u16::<NetworkEndian>()?;
    let src = cursor.read_u32::<NetworkEndian>()?;
    let dst = cursor.read_u32::<NetworkEndian>()?;

    Ok((IpHeader {
        version: IpVersion::Four,
        protocol: IpProto::from(protocol),
        tos,
        len: total_len,
        id,
        flags,
        fragment_offset,
        ttl,
        checksum,
        source: Ipv4Addr::from(src).into(),
        destination: Ipv4Addr::from(dst).into(),
    }, &buf[header_len as usize * 4..]))
}

#[derive(Debug)]
pub enum IpVersion {
    Four,
    Six,
}

use std::net::Ipv4Addr;
use std::net::IpAddr;

#[derive(Debug)]
pub struct IpHeader {
    pub version: IpVersion,
    pub protocol: IpProto,
    pub tos: u8,
    pub len: u16,
    pub id: u16,
    pub flags: u8,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub checksum: u16,
    pub source: IpAddr,
    pub destination: IpAddr,
}

#[derive(Debug, PartialEq)]
pub enum IpProto {
    Udp,
    Tcp,
    Unknown(u8),
}

impl IpHeader {
    pub fn parse_headers<'a>(&self, buf: &'a [u8]) -> io::Result<(IpProtoHeaders, &'a [u8])> {
        match &self.protocol {
            &IpProto::Tcp => parse_tcp_header(buf).map(|(h, data)| (IpProtoHeaders::Tcp(h), data)),
            _ => unimplemented!(),
        }
    }
}

impl From<u8> for IpProto {
    fn from(p: u8) -> Self {
        match p {
            17 => IpProto::Udp,
            6 => IpProto::Tcp,
            x => IpProto::Unknown(x),
        }
    }
}

#[derive(Debug)]
pub enum IpProtoHeaders {
    Tcp(TcpHeader),
}

impl IpProtoHeaders {
    pub fn into_tcp_header(self) -> Result<TcpHeader, IpProtoHeaders> {
        match self {
            IpProtoHeaders::Tcp(x) => Ok(x),
            // y => Err(y)
        }
    }
}

