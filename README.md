# readpcap

Quick and dirty support for reading pcap files in order to test a tokio-io codec.

I wrote this initially to support testing my
[`eventstore-tcp`](https://github.com/koivunej/eventstore-tcp) against packet
capture containing packets sent by the original client library and EventStore
server.  Figured it would be simpler than to write a protocol dissector...
The end result is not pretty or idiomatic rust but it might help you. Patches
are most welcome.

Currently the library supports:

 * reading the basic pcap structures
 * ethernet frames (partial)
 * ip headers (partial)
 * tcp headers (partial)
 * tcp connections (client initiated and shut down, probably misbehaves on retransmissions)
 * bring-your-own tcp connection tracking (in the example)

I've only used the library on samples acquired by tapping into loopback device
connections so there is probably inadequate support for any real-life packet
captures with tcp retransmissions and whatnot.

If you want to experiment with this against your own
[`tokio_io::codec::Decoder`](https://docs.rs/tokio-io/0.1/tokio_io/codec/trait.Decoder.html)
implementation, take a look at the `examples/read-eventstore_tcp-pcap.rs` which
I've tried to annotate as well as possible.

The example:

 * assumes every starting tcp connection is an eventstore-tcp connection, which
   can be successfully decoded using the provided codec(s)
 * shows how to:
    * select only the tcp frames
    * track connections
    * feed tracked connections data
    * decode the buffered data into `Decoder::Item`
