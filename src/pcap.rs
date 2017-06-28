use std::fmt;
use std::io;
use std::time::Duration;
use byteorder::ReadBytesExt;
use byteorder::LittleEndian;
use byteorder::BigEndian;
use byteorder::NetworkEndian;
use byteorder::ByteOrder;

/// Pcap file endianess
#[derive(Debug)]
pub enum Endianess {
    LE,
    BE,
}

/// Pcap file version.
#[derive(Debug)]
pub struct Version {
    major: u16,
    minor: u16,
}

/// Determines the frame type inside the pcap file
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

impl<'a> AsRef<[u8]> for MAC<'a> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Enumeration of frames as they appear in the pcap file, currently only EthernetFrame.
/// Inner type should be determined by the DataLink value in the global header.
#[derive(Debug)]
pub enum Frame<'a> {
    Ethernet(EthernetFrame<'a>),
}

impl<'a> Frame<'a> {
    fn parse_ethernet(packet: &'a [u8]) -> Self {
        let len = match NetworkEndian::read_u16(&packet[12..14]) as usize {
            x if x <= 1500 => unimplemented!(),
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

/// Frame for DataLink::Ethernet
pub struct EthernetFrame<'a> {
    source: MAC<'a>,
    destination: MAC<'a>,
    len: u16,
    payload: &'a [u8],
}

impl<'a> fmt::Debug for EthernetFrame<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        // omit payload
        fmt.debug_struct("EthernetFrame")
            .field("src", &self.source)
            .field("dst", &self.destination)
            .field("len", &self.len)
            .finish()
    }
}

/// The main pcap file header.
#[derive(Debug)]
pub struct GlobalHeader {
    endianess: Endianess,
    timestamps: TimestampPrecision,
    version: Version,
    local_offset_seconds: i32,
    sigfigs: u32,
    snaplen: u32,
    datalink: DataLink,
}

/// Depending on the magic bytes in the pcap file, the timestamps can be either nanos or millis.
#[derive(Debug)]
enum TimestampPrecision {
    Millis,
    Nanos,
}

impl TimestampPrecision {

    fn read_duration<E: ByteOrder, R: io::Read>(&self, reader: &mut R) -> io::Result<Duration> {
        let seconds = reader.read_u32::<E>()?;
        let subsec = reader.read_u32::<E>()?;

        Ok(self.to_duration(seconds, subsec))
    }

    fn to_duration(&self, seconds: u32, subsec: u32) -> Duration {
        use self::TimestampPrecision::*;
        match *self {
            Millis => Duration::new(seconds as u64, subsec * 1_000),
            Nanos => Duration::new(seconds as u64, subsec)
        }
    }
}

impl GlobalHeader {
    pub fn read_packet_header<R: io::Read>(&self, reader: &mut R) -> io::Result<PacketHeader> {
        match self.endianess {
            Endianess::LE => PacketHeader::read_from::<LittleEndian, R>(&self.timestamps, reader),
            Endianess::BE => PacketHeader::read_from::<BigEndian, R>(&self.timestamps, reader),
        }
    }

    pub fn parse_frame<'a>(&self, buf: &'a [u8]) -> Frame<'a> {
        self.datalink.read_frame(buf)
    }

    /// Reads the GlobalHeader from for example a file.
    pub fn read_from<R: io::Read>(reader: &mut R) -> io::Result<Self> {

        let (endianess, nanos) = read_magic(reader)?;

        return match endianess {
            x @ Endianess::LE => read_header::<LittleEndian, R>(x, nanos, reader),
            x @ Endianess::BE => read_header::<BigEndian, R>(x, nanos, reader),
        };

        fn read_magic<R: io::Read>(reader: &mut R) -> io::Result<(Endianess, bool)> {
            let mut magic = [0u8; 4];
            reader.read_exact(&mut magic[..])?;

            match LittleEndian::read_u32(&magic[..]) {
                0xa1b2c3d4 => Ok((Endianess::LE, false)),
                0xa1b23c4d => Ok((Endianess::LE, true)),
                0xd4c3b2a1 => Ok((Endianess::BE, false)),
                0x4d3cb2a1 => Ok((Endianess::BE, true)),
                x => Err(io::Error::new(io::ErrorKind::InvalidData, format!("Unexpected magic bytes: 0x{:x}", x))),
            }
        }

        fn read_header<E: ByteOrder, R: io::Read>(endianess: Endianess, nanos: bool, reader: &mut R) -> io::Result<GlobalHeader> {
            let major = reader.read_u16::<E>()?;
            let minor = reader.read_u16::<E>()?;

            let version = Version { major, minor };

            let local_offset_seconds = reader.read_i32::<E>()?;
            let sigfigs = reader.read_u32::<E>()?;
            let snaplen = reader.read_u32::<E>()?;
            let datalink = match reader.read_u32::<E>()? {
                1 => DataLink::Ethernet,
                x => DataLink::Unknown(x),
            };

            Ok(GlobalHeader {
                endianess,
                timestamps: if nanos { TimestampPrecision::Nanos } else { TimestampPrecision::Millis },
                version,
                local_offset_seconds,
                sigfigs,
                snaplen,
                datalink,
            })
        }
    }
}

/// Header before each captured packet.
#[derive(Debug)]
pub struct PacketHeader {
    pub offset: Duration,
    recorded_len: u32,
    original_len: u32,
}

impl PacketHeader {
    /// Returns true if a full packet was captured
    pub fn is_full(&self) -> bool {
        self.recorded_len == self.original_len
    }

    /// Reads the next packet from the given reader into the given buffer.
    /// Buffer is assumed to be empty.
    pub fn read_packet_into<R: io::Read>(&self, reader: &mut R, buf: &mut Vec<u8>) -> io::Result<()> {
        assert_eq!(buf.len(), 0);
        let recorded_len = self.recorded_len as usize;

        buf.reserve(recorded_len);
        unsafe { buf.set_len(recorded_len); }

        reader.read_exact(&mut buf[..recorded_len])
    }

    /// Instead of copying, pick the next recorded_len bytes off the beginning of the given slice
    /// (possibly backed by an mmap).
    pub fn packet_slice<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        let recorded_len = self.recorded_len as usize;
        &buf[..recorded_len]
    }

    fn read_from<E: ByteOrder, R: io::Read>(timestamps: &TimestampPrecision, reader: &mut R) -> io::Result<PacketHeader> {
        let offset = timestamps.read_duration::<E, R>(reader)?;

        let recorded_len = reader.read_u32::<E>()?;
        let original_len = reader.read_u32::<E>()?;

        Ok(PacketHeader {
            offset,
            recorded_len,
            original_len,
        })
    }
}
