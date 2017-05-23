use std::io;
use byteorder::ReadBytesExt;
use byteorder::NetworkEndian;

pub mod connection;
pub use self::connection::ConnectionId;
pub use self::connection::Connection;
pub use self::connection::Direction;

#[derive(Debug)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub sequence_number: u32,
    pub acknowledgement_number: u32,
    pub offset: u8,
    pub reserved: u8,
    pub flags: u8,
    pub window: u16,
    pub checksum: u16,
    pub urgent_pointer: u16,
    // options: Vec<TcpOptionValue>,
}

impl TcpHeader {
    pub fn is_ack(&self) -> bool {
        self.flags & 0b0001_0000 != 0
    }
    pub fn is_psh(&self) -> bool {
        self.flags & 0b0000_1000 != 0
    }
    pub fn is_rst(&self) -> bool {
        self.flags & 0b0000_0100 != 0
    }
    pub fn is_syn(&self) -> bool {
        self.flags & 0b0000_0010 != 0
    }
    pub fn is_fin(&self) -> bool {
        self.flags & 0b0000_0001 != 0
    }
}

pub fn parse_tcp_header<'a>(buf: &'a [u8]) -> io::Result<(TcpHeader, &'a [u8])> {
    let mut cursor = io::Cursor::new(buf);

    let src_port = cursor.read_u16::<NetworkEndian>()?;
    let dst_port = cursor.read_u16::<NetworkEndian>()?;
    let sequence_number = cursor.read_u32::<NetworkEndian>()?;
    let acknowledgement_number = cursor.read_u32::<NetworkEndian>()?;
    let (offset, reserved) = {
        let byte = cursor.read_u8()?;
        (byte >> 4, byte & 0xf)
    };
    let flags = cursor.read_u8()?;
    let window = cursor.read_u16::<NetworkEndian>()?;
    let checksum = cursor.read_u16::<NetworkEndian>()?;
    let urgent_pointer = cursor.read_u16::<NetworkEndian>()?;

    let len = offset as usize * 4;

    if len > 20 {
        // options
        for _ in 0..(len - 20) { cursor.read_u8()?; }
    }

    let pos = cursor.position() as usize;
    assert_eq!(pos, len);

    Ok((TcpHeader {
        src_port,
        dst_port,
        sequence_number,
        acknowledgement_number,
        offset,
        reserved,
        flags,
        window,
        checksum,
        urgent_pointer,
        // options
    }, &buf[pos..]))
}
