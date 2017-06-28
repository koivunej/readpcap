extern crate readpcap;
extern crate eventstore_tcp;
extern crate tokio_io;

use std::io;
use std::env;
use std::fs;
use std::process;
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::time::Duration;

use readpcap::pcap;
use readpcap::ip::IpProto;
use readpcap::ip::parse_ip_header;
use readpcap::tcp::ConnectionId;
use readpcap::tcp::Connection;
use readpcap::tcp::DecodedConnection;
use readpcap::tcp::Direction::{self, ClientServer, ServerClient};

use tokio_io::codec::Decoder;
use eventstore_tcp::codec::PackageCodec;
use eventstore_tcp::package::Package;

fn main() {
    if env::args().count() != 2 {
        eprintln!("Usage: {} INPUT", env::args().next().unwrap());
        eprintln!("where INPUT is a packet capture file,");
        eprintln!("            containing only eventstore-tcp readable tcp frames");
        process::exit(1);
    }

    let filename = env::args().skip(1).next().expect("INPUT argument required");
    let mut file = fs::File::open(filename).expect("Failed to open INPUT file");

    print_operation_durations(&mut file).unwrap();
}

// this outer function handles the eventstore-tcp specific matters, using the
// `for_each_decoded_frame` "helper" to actually go through all of the connections
fn print_operation_durations(file: &mut fs::File) -> io::Result<()> {

    // when protocol level operation started
    let mut operations = HashMap::new();
    let mut decoded = [0u32, 0u32];

    fn decoder_factory(_: ConnectionId) -> (PackageCodec, PackageCodec) {
        // client and server codec
        (PackageCodec, PackageCodec)
    }

    let connections = for_each_decoded_frame(file, decoder_factory, |dir, elapsed, frame| {
        match (dir, frame) {
            (ClientServer, Package { correlation_id, .. }) => {
                assert_eq!(operations.insert(correlation_id, elapsed), None);
                decoded[0] += 1;
            },
            (ServerClient, Package { correlation_id, .. }) => {
                // print an estimate for operation delay by using the capture timestamps
                let elapsed = elapsed - operations.remove(&correlation_id).unwrap();
                decoded[1] += 1;
                println!("{}", elapsed.as_secs() * 1_000 + elapsed.subsec_nanos() as u64 / 1_000_000);
            },
        }
    })?;

    if !connections.is_empty() {
        eprintln!("Packet capture ended with {} remaining connections:", connections.len());
        for (key, _) in connections {
            eprintln!("  => {:?}", key);
        }
    }

    eprintln!("Decoded frames: ClientServer {}, ServerClient {}", decoded[0], decoded[1]);

    Ok(())
}

// Haven't yet written any iterator alike api for scanning the file but to illustrate the use of
// the library this function handles all readpcap specific parts and the calling function handles
// the protocol specific parts with the callback.
//
// This function could be called `boilerplate` as well.
fn for_each_decoded_frame<DF, D, F>(
        file: &mut fs::File,
        decoder_factory: DF,
        mut callback: F) -> io::Result<HashMap<ConnectionId, DecodedConnection<D>>>
    where DF: Fn(ConnectionId) -> (D, D),
          D: Decoder,
          D::Error: std::fmt::Debug,
          F: FnMut(Direction, Duration, D::Item) -> ()
{
    let header = pcap::GlobalHeader::read_from(file)?;

    // keep a map of ConnectionId => Connection
    let mut connections = HashMap::new();

    // buffer for packet data ...
    // TODO: use mmap
    let mut buf = Vec::new();

    // for printing relative time offsets, keep the first timestamp
    let mut first_offset = None;

    loop {
        // this is required
        buf.clear();

        let packet_header = match header.read_packet_header(file) {
            Ok(hdr) => hdr,
            Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                // assume we have read through the whole file if we cannot read the next header
                break
            },
            Err(e) => return Err(e),
        };

        assert!(packet_header.is_full());

        first_offset = first_offset.or(Some(packet_header.offset));

        packet_header.read_packet_into(file, &mut buf).unwrap();

        let frame = header.parse_frame(&buf);
        let (ipheader, next) = parse_ip_header(frame.body()).unwrap();

        // this example assumes that all tcp connections that belong to a connection started in the
        // capture are decodeable with the codec.
        if ipheader.protocol != IpProto::Tcp {
            continue;
        }

        let (tcpheader, next) = ipheader.parse_headers(next).unwrap();
        let tcpheader = tcpheader.into_tcp_header().unwrap();

        let key = ConnectionId::new(&ipheader, &tcpheader);

        let remove = {
            // this mapping is probably wrong in some cases but haven't figured out a better one.
            // basically store the connection with key = (client_addr, server_addr) but try to find
            // it with (server_addr, client_addr) as well.
            let mut connection = if connections.contains_key(&key.wrapped()) {
                connections.get_mut(&key.wrapped()).unwrap()
            } else if connections.contains_key(&key) {
                connections.get_mut(&key).unwrap()
            } else if let Some(conn) = Connection::start(&ipheader, &tcpheader) {
                // wrap the created connection with these decoders in ClientServer, ServerClient
                // directions. note that the connection is created on first SYN so it's not really
                // a full tcp connection but hopefully it will become one.
                let (client_decoder, server_decoder) = decoder_factory(conn.key());

                let wrapped = conn.decoded(client_decoder, server_decoder);

                match connections.entry(key) {
                    Entry::Vacant(ve) => Some(ve.insert(wrapped)),
                    _ => panic!("Entry cannot be occupied as we just checked it"),
                };

                assert!(next.is_empty(), "connection contains data on first SYN");
                continue;
            } else {
                // unknown connection, packet capture does not contain data for its start
                continue;
            };

            // feed the packet to the tcp connection which will panic if it does not support this
            // kind of packet right now
            connection.advance(&ipheader, &tcpheader, next);

            let elapsed = packet_header.offset - first_offset.unwrap();

            loop {
                // now finally loop through the now decodable frames using the codec
                match connection.decode().unwrap() {
                    None => break,
                    Some((dir, decoded)) => callback(dir, elapsed, decoded),
                }
            }

            // if the connection thinks it's done, return it's key
            if connection.is_done() {
                Some(connection.key())
            } else {
                None
            }
        };

        if let Some(key) = remove {
            assert!(connections.remove(&key).is_some());
        }
    }

    // return the possibly remaining connections
    Ok(connections)
}
