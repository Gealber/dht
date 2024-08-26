## ADNL UDP(WIP)

This is an internal doc, not official at all, describing the ADNL over UDP protocol in a more formal way. Given that the official documentation to be honest is just an example, which lack formality. The description of ADNL over TCP by other hand is way better, at least more structured. In the whitepaper of TON there's a quite simplistic description of the protocol without any details. In general the networking documentation of TON is quite bad. So I'll try to do my best at least with ADNL over UDP.

## Requirements

Before you start diving in, there are some previous knowledge that you should have.

1. Basics about UDP, a formal description of it can be found in [RFC 768](https://datatracker.ietf.org/doc/html/rfc768), but I any programming language has an implementation of it. Even the formal description is quite short, UDP is basic.
2. TL serializer and parser. ADNL uses [TL(Type Language)](https://core.telegram.org/mtproto/TL) to serialize the data that will be transmitted. This is quite particular way of serialization, so not sure if you will find a great variety of libraries that implement it. Here I list you the ones I found:
    1. [(Go) xssnick/tonutils-go/tl](https://github.com/xssnick/tonutils-go/tree/master/tl).
    2. [(Go) in this repository](https://github.com/Gealber/dht/tree/master/tl) you can also find one I wrote, still with a lot of cases missing.
    3. [(C++) ton-blockchain/ton/tl](https://github.com/ton-blockchain/ton/tree/master/tl). This would be your source of truth I think.
    4. [(Rust) ston-fi/tonlib-rs/src/tl](https://github.com/ston-fi/tonlib-rs/tree/main/src/tl).
3. Get familiar with [ECDH which stands for Elliptic Curve Diffie-Helman](https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman), not in depth but at least try to understand a basic example of it. I think the best resources I found for it at the moment are these:
    1. [cryptobook.nakov blog](https://cryptobook.nakov.com/asymmetric-key-ciphers/ecdh-key-exchange), you can find an example written in Python there.
    2. [ECDH encryption using ed25519 keys](https://hodo.dev/posts/post-48-ecdh-over-ed25519/). With an example written in Golang.

## Description

Quoting [TON whitepaper](https://ton.org/whitepaper.pdf):

> The cornerstone in building the TON networking protocols is the (TON) Abstract (Datagram) Network Layer. It enables all nodes to assume certain "network identities", represented by 256-bit "abstract network addresses", and communicate (send datagrams to each other, as a first step) using only these 256-bit network addresses to identify the sender and the receiver.

The description of the ADNL protocol in this document will be in the context of its usage on the TON blockchain.

## Packet Format

Communication on ADNL protocol is carried out through the share of datagrams that followed [adnl.packetContents format](https://github.com/ton-blockchain/ton/blob/140320b0dbe0bdd9fd954b6633a3677acc75a8e6/tl/generate/scheme/ton_api.tl#L82). The definition of this TL-object is described as follows:

```TL
adnl.packetContents 
  rand1:bytes 
  flags:# 
  from:flags.0?PublicKey 
  from_short:flags.1?adnl.id.short
  message:flags.2?adnl.Message 
  messages:flags.3?(vector adnl.Message)
  address:flags.4?adnl.addressList 
  priority_address:flags.5?adnl.addressList
  seqno:flags.6?long 
  confirm_seqno:flags.7?long 
  recv_addr_list_version:flags.8?int
  recv_priority_addr_list_version:flags.9?int
  reinit_date:flags.10?int 
  dst_reinit_date:flags.10?int
  signature:flags.11?bytes 
  rand2:bytes 
        = adnl.PacketContents;
```

This is the TL definition, I'll try to explain better the components of that TL definition in the following table.

**adnl.packetContents**

**Notes**: Fields which doesn't affect flags byte position are  maked in **flag byte position** column with value `_`. Types that are referenced in the table like `PublicKey` can be found defined in [ton_api.tl](https://github.com/ton-blockchain/ton/blob/140320b0dbe0bdd9fd954b6633a3677acc75a8e6/tl/generate/scheme/ton_api.tl#L46). Some of these types are *explicitly* defined and some are not. The ones that are not, like `PublicKey`, it just means that it accepts one of the available `PublicKey` types. For example, `from` field takes `PublicKey` type which is not explicitely define, meaning that accepts one of the available types of `PublicKey` defined in [ton_api.tl](https://github.com/ton-blockchain/ton/blob/140320b0dbe0bdd9fd954b6633a3677acc75a8e6/tl/generate/scheme/ton_api.tl#L46), `pub.unenc, pub.ed25519, pub.aes, or pub.overlay`.


| Field name | flag byte position | type | description |
|------------|--------------------|------|-------------|
|rand1       | _ | bytes| random 7 or 15 bytes, why 7 or 15? No idea |
| flags | _ | int | flags marks which fields of the TL-object are present |
| from | 0 | PublicKey | packet sender public key |
| from_short | 1 | adnl.id.short | node identifier |
| message | 2 | adnl.Message | a single unit of [adnl.Message](https://github.com/ton-blockchain/ton/blob/140320b0dbe0bdd9fd954b6633a3677acc75a8e6/tl/generate/scheme/ton_api.tl#L130) checkout differents types on TL definition |
| messages | 3 | (vector adnl.Message) | several units of adnl.Message |
| address | 4 | adnl.addressList | a list of [adnl.Address](https://github.com/ton-blockchain/ton/blob/140320b0dbe0bdd9fd954b6633a3677acc75a8e6/tl/generate/scheme/ton_api.tl#L65) |
| priority_address | 5 | adnl.addressList | a list of [adnl.Address](https://github.com/ton-blockchain/ton/blob/140320b0dbe0bdd9fd954b6633a3677acc75a8e6/tl/generate/scheme/ton_api.tl#L65) |
| seqno | 6 | long | sequence number of the packet, in case the receiver already proccessed a packet with this seqno, the packet will be dropped |
| confirm_seqno | 7 | long | latest confirmed sequence number, if confirm_seqno > out_seqno in the receiver node the packet will be dropped |
| recv_addr_list_version | 8 | int | no idea why is this needed yet |
| recv_priority_addr_list_version | 9 | int | no idea why is this needed yet|
| reinit_date | 10 | int | current timestamp of sender node, more about this field later |
| dst_reinit_date | 10 | int | timestamp, more about this field later |
| signature | 11 | bytes | packet signature, more about this field later |
| rand2 | _ | bytes |  random 7 or 15 bytes |

Fields which flag position byte is not set, shouldn't be included in the payload serialized. For example if position byte **2** is not set in `flags`, `message` field shouldn't be included in the resulting data serialized.