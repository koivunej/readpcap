extern crate readpcap;
extern crate eventstore_tcp;

use std::env;
use std::fs;
use std::collections::HashMap;
use std::collections::hash_map::Entry;

use readpcap::pcap;
use readpcap::ip::IpProto;
use readpcap::ip::parse_ip_header;
use readpcap::tcp::ConnectionId;
use readpcap::tcp::Connection;
use readpcap::tcp::Direction::*;

use eventstore_tcp::codec::PackageCodec;
use eventstore_tcp::package::Package;

fn main() {

    let filename = env::args().skip(1).next().unwrap_or_else(|| panic!("INPUT argument required"));

    let mut file = fs::File::open(filename).expect("Failed to open INPUT file");

    let header = pcap::read_header(&mut file).unwrap();

    println!("Header: {:?}", header);

    //let mut connections = Vec::new();
    let mut conn_map = HashMap::new();
    let mut operations = HashMap::new();
    let mut buf = Vec::new();

    let mut first_offset = None;

    for _ in 0.. {
        //println!("processing frame {}", i);
        buf.clear();

        let packet_header = header.read_packet_header(&mut file).unwrap();
        /*println!("-----------");
        println!("{:?}", packet_header);*/
        assert!(packet_header.is_full());
        first_offset = first_offset.or(Some(packet_header.offset));

        let elapsed = packet_header.offset - first_offset.unwrap();

        packet_header.read_packet_into(&mut file, &mut buf).unwrap();

        let frame = header.parse_frame(&buf);
        //println!("{:?}", frame);
        // there could be frame.parse_header()
        let (ipheader, next) = parse_ip_header(frame.body()).unwrap();
        //println!("{:?}", ipheader);

        if ipheader.protocol != IpProto::Tcp {
            continue;
        }

        let (tcpheader, next) = ipheader.parse_headers(next).unwrap();
        let tcpheader = tcpheader.into_tcp_header().unwrap();
        // println!("{:?}", tcpheader);

        let key = ConnectionId::new(&ipheader, &tcpheader);

        let remove = {
            let mut connection = if conn_map.contains_key(&key.wrapped()) {
                conn_map.get_mut(&key.wrapped()).unwrap()
            } else if conn_map.contains_key(&key) {
                conn_map.get_mut(&key).unwrap()
            } else if let Some(conn) = Connection::start(&ipheader, &tcpheader) {
                match conn_map.entry(key) {
                    Entry::Vacant(ve) => Some(ve.insert(conn.decoded(PackageCodec, PackageCodec))),
                    _ => unreachable!(),
                };
                println!("now tracking {} connections", conn_map.len());
                assert!(next.is_empty());
                continue;
            } else {
                continue;
            };

            connection.advance(&ipheader, &tcpheader, next);

            loop {
                match connection.decode().unwrap() {
                    None => break,
                    Some((ClientServer, Package { correlation_id, .. })) => assert_eq!(operations.insert(correlation_id, elapsed), None),
                    Some((ServerClient, Package { correlation_id, .. })) => {
                        let elapsed = elapsed - operations.remove(&correlation_id).unwrap();
                        println!("{}", elapsed.as_secs() * 1_000 + elapsed.subsec_nanos() as u64 / 1_000_000);
                    }
                }
            }

            if connection.is_done() {
                Some(connection.key())
            } else {
                None
            }
        };

        if let Some(key) = remove {
            conn_map.remove(&key);
        }
    }
}
