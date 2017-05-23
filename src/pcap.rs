use std::fmt;
use std::io;
use std::time::Duration;
use byteorder::ReadBytesExt;
use byteorder::LittleEndian;
use byteorder::BigEndian;
use byteorder::NetworkEndian;
use byteorder::ByteOrder;

#[derive(Debug)]
pub enum Endianess {
    LE,
    BE,
}

#[derive(Debug)]
pub struct Version {
    major: u16,
    minor: u16,
}

#[derive(Debug, Clone, Copy)]
pub enum DataLink {
    Unknown(u32),
    Ethernet,
}

impl DataLink {
    fn read_frame<'a>(&self, packet: &'a [u8]) -> Frame<'a> {
        match *self {
            DataLink::Ethernet => Frame::parse_ethernet(packet),
            _ => unimplemented!(),
        }
    }
}

pub struct MAC<'a>(&'a [u8]);

impl<'a> fmt::Display for MAC<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "{:x}{:x}{:x}:{:x}{:x}{:x}", self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5])
    }
}

impl<'a> fmt::Debug for MAC<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        <Self as fmt::Display>::fmt(self, fmt)
    }
}

#[derive(Debug)]
pub enum Frame<'a> {
    Ethernet(EthernetFrame<'a>),
}

pub struct EthernetFrame<'a> {
    source: MAC<'a>,
    destination: MAC<'a>,
    len: u16,
    payload: &'a [u8],
}

impl<'a> fmt::Debug for EthernetFrame<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("EthernetFrame")
            .field("src", &self.source)
            .field("dst", &self.destination)
            .field("len", &self.len)
            .finish()
    }
}

impl<'a> Frame<'a> {
    fn parse_ethernet(packet: &'a [u8]) -> Self {
        let len = match NetworkEndian::read_u16(&packet[12..14]) as usize {
            x if x <= 1500 => x,
            _ => packet.len() - 14,
        };
        Frame::Ethernet(EthernetFrame {
            source: MAC(&packet[0..6]),
            destination: MAC(&packet[6..12]),
            len: len as u16,
            payload: &packet[14..],
        })
    }

    pub fn body(&'a self) -> &'a [u8] {
        match self {
            &Frame::Ethernet(EthernetFrame { payload, .. }) => payload,
        }
    }
}

#[derive(Debug)]
pub struct GlobalHeader {
    endianess: Endianess,
    nanosecond_timestamps: bool,
    version: Version,
    local_offset_seconds: i32,
    sigfigs: u32,
    snaplen: u32,
    datalink: DataLink,
}

#[derive(Debug)]
pub struct PacketHeader {
    pub offset: Duration,
    recorded_len: u32,
    original_len: u32,
}

impl PacketHeader {
    pub fn is_full(&self) -> bool {
        self.recorded_len == self.original_len
    }

    pub fn read_packet_into<R: io::Read>(&self, reader: &mut R, buf: &mut Vec<u8>) -> io::Result<()> {
        let recorded_len = self.recorded_len as usize;

        if buf.len() < recorded_len {
            buf.reserve(recorded_len);
            unsafe { buf.set_len(recorded_len); }
        }

        reader.read_exact(&mut buf[..])
    }
}

impl GlobalHeader {
    pub fn read_packet_header<R: io::Read>(&self, reader: &mut R) -> io::Result<PacketHeader> {
        match self.endianess {
            Endianess::LE => read_packet_header::<LittleEndian, _>(self.nanosecond_timestamps, reader),
            Endianess::BE => read_packet_header::<BigEndian, _>(self.nanosecond_timestamps, reader),
        }
    }

    pub fn parse_frame<'a>(&self, buf: &'a [u8]) -> Frame<'a> {
        self.datalink.read_frame(buf)
    }
}

fn read_packet_header<E: ByteOrder, R: io::Read>(nanos: bool, reader: &mut R) -> io::Result<PacketHeader> {
    Ok(PacketHeader {
        offset: parse_packet_header_offset(reader.read_u32::<E>()?, reader.read_u32::<E>()?, nanos),
        recorded_len: reader.read_u32::<E>()?,
        original_len: reader.read_u32::<E>()?,
    })
}

fn parse_packet_header_offset(seconds: u32, subsec: u32, nanos: bool) -> Duration {
    if nanos {
        Duration::new(seconds as u64, subsec)
    } else {
        Duration::new(seconds as u64, subsec * 1_000)
    }
}

pub fn read_header<R: io::Read>(reader: &mut R) -> io::Result<GlobalHeader> {
    let mut magic = [0u8; 4];
    reader.read_exact(&mut magic[..])?;

    match LittleEndian::read_u32(&magic[..]) {
        0xa1b2c3d4 => read_header_rest::<LittleEndian, _>(Endianess::LE, false, reader),
        0xa1b23c4d => read_header_rest::<LittleEndian, _>(Endianess::LE, true, reader),
        0xd4c3b2a1 => read_header_rest::<BigEndian, _>(Endianess::BE, false, reader),
        0x4d3cb2a1 => read_header_rest::<BigEndian, _>(Endianess::BE, true, reader),
        x => Err(io::Error::new(io::ErrorKind::InvalidData, format!("Unexpected magic bytes: {:?}", x))),
    }
}

fn read_header_rest<E: ByteOrder, R: io::Read>(endianess: Endianess, nanos: bool, reader: &mut R) -> io::Result<GlobalHeader> {
    let major = reader.read_u16::<E>()?;
    let minor = reader.read_u16::<E>()?;

    let version = Version { major, minor };

    let local_offset_seconds = reader.read_i32::<E>()?;
    let sigfigs = reader.read_u32::<E>()?;
    let snaplen = reader.read_u32::<E>()?;
    let datalink = read_datalink::<E, _>(reader)?;

    Ok(GlobalHeader {
        endianess,
        nanosecond_timestamps: nanos,
        version,
        local_offset_seconds,
        sigfigs,
        snaplen,
        datalink,
    })
}

fn read_datalink<E: ByteOrder, R: io::Read>(reader: &mut R) -> io::Result<DataLink> {
    Ok(match reader.read_u32::<E>()? {
        1 => DataLink::Ethernet,
        x => DataLink::Unknown(x),
    })
}

