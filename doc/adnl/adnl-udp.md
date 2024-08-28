## ADNL UDP(WIP)

This is an internal doc, not official at all, describing the ADNL over UDP protocol in a more formal way. Given that the official documentation to be honest lacks formality. The description has a good approach, that is explaining by example, but still there are so many gaps that should be included. Even that the official documentaion lacks formality, is still way better than the description on the TON whitepaper. In the whitepaper of TON there's a quite simplistic description of the protocol without any details, which gives the impression that the implementation of the protocol was only discussed internally between the developers of the TON blockchain. I understand that the whitepaper is not intended for that, but a document dedicated to the protocol that constitute the core of the networking I think is needed. In general the networking documentation of TON is quite bad, so I'll try to do my best at least with ADNL over UDP. 

## Requirements

Before you start diving in, there are some previous knowledge that you should have.

1. Basics about UDP, a formal description of it can be found in [RFC 768](https://datatracker.ietf.org/doc/html/rfc768), but any programming language has an implementation of it. Even the formal description is quite short, UDP is basic.
2. TL serializer and parser. ADNL uses [TL(Type Language)](https://core.telegram.org/mtproto/TL) to serialize the data that will be transmitted. This is quite particular way of serialization, so not sure if you will find a great variety of libraries that implement it. Here I list you the ones I found:
    1. [(Go) xssnick/tonutils-go/tl](https://github.com/xssnick/tonutils-go/tree/master/tl).
    2. [(Go) in this repository](https://github.com/Gealber/dht/tree/master/tl) you can also find one I wrote, still with a lot of cases missing.
    3. [(C++) ton-blockchain/ton/tl](https://github.com/ton-blockchain/ton/tree/master/tl). This would be your source of truth I think.
    4. [(Rust) ston-fi/tonlib-rs/src/tl](https://github.com/ston-fi/tonlib-rs/tree/main/src/tl).
3. Get familiar with [ECDH which stands for Elliptic Curve Diffie-Helman](https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman), not in depth but at least try to understand a basic example of it. I think the best resources I found for it at the moment are these:
    1. [cryptobook.nakov blog](https://cryptobook.nakov.com/asymmetric-key-ciphers/ecdh-key-exchange), you can find an example written in Python there.
    2. [ECDH encryption using ed25519 keys](https://hodo.dev/posts/post-48-ecdh-over-ed25519/). With an example written in Golang.

## Note

1. All the TL definition used here can be found in [tl/generate/scheme](https://github.com/ton-blockchain/ton/tree/master/tl/generate/scheme).
2. This article might have incorrect or incomplete information, so feel free to suggest a correction of it.

## Description

Quoting [TON whitepaper](https://ton.org/whitepaper.pdf):

> The cornerstone in building the TON networking protocols is the (TON) Abstract (Datagram) Network Layer. It enables all nodes to assume certain "network identities", represented by 256-bit "abstract network addresses", and communicate (send datagrams to each other, as a first step) using only these 256-bit network addresses to identify the sender and the receiver.

The description of the ADNL protocol in this document will be in the context of its usage on the TON blockchain.

## Packet Format

Packet data follows a TL-object called `adnl.packetContents`. Here is a description of it.

### adnl.packetContents

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
| reinit_date | 10 | int | current timestamp of sender noded, needs to be bigger than last reinit_date sent, otherwise packet will be dropped |
| dst_reinit_date | 10 | int | timestamp |
| signature | 11 | bytes | packet signature signed with sender private key |
| rand2 | _ | bytes |  random 7 or 15 bytes |

### Details on some fields

**dst_reinit_date**

This field when received by a node has a particular requirement in the code implementation that I don't know if it's a bug, or just a useless field included. There are two checks on this field that basically will restrict `dst_reinit_date` to be `dst_reinit_date <=0` or `dst_reinit_date = d`. The first checked performed on the received field, on method [AdnlPeerPairImpl::receive_packet_checked](https://github.com/ton-blockchain/ton/blob/140320b0dbe0bdd9fd954b6633a3677acc75a8e6/adnl/adnl-peer.cpp#L117), drop messages packets which `dst_reinit_date > d`:

```C++
auto d = Adnl::adnl_start_time();
if (packet.dst_reinit_date() > d) {
  VLOG(ADNL_WARNING) << this << ": dropping IN message: too new our reinit date " << packet.dst_reinit_date();
  return;
}

// ... later in same method

if (packet.dst_reinit_date() > 0 && packet.dst_reinit_date() < d) {
    if (!packet.addr_list().empty()) {
      auto addr_list = packet.addr_list();
      if (packet.remote_addr().is_valid() && addr_list.size() == 0) {
        VLOG(ADNL_DEBUG) << "adding implicit address " << packet.remote_addr();
        addr_list.add_udp_address(packet.remote_addr());
      }
      update_addr_list(std::move(addr_list));
    }
    if (!packet.priority_addr_list().empty()) {
      update_addr_list(packet.priority_addr_list());
    }
    VLOG(ADNL_NOTICE) << this << ": dropping IN message old our reinit date " << packet.dst_reinit_date()
                      << " date=" << d;
    auto M = OutboundAdnlMessage{adnlmessage::AdnlMessageNop{}, 0};
    send_message(std::move(M));
    return;
  }
```

These two checks are basically dropping all values of `dst_reinit_date`, at least they are `0` or `d`. No comments on the code, or in any part about the rational of this. Keep this in mind when implementing a client, to avoid your packages been dropped for now reason.

## Comunication mechanisms

### First packet format

The communication between two peers through ADNL, doesn't consists only on sharing serialized `adnl.packetContents`, given that these packets need to be encrypted in some way before sharing with the other peer. The approach for this encryption is using ECDH, checkout **Requirements** section to look for practical examples of how ECDH is performed. Apart from the encryption peers also will need to check the autenticity of the packet sent. Given this, makes sense that the format of the first packet exchanged follow this structure:

```
0                                         31
+-----------------------------------------+
| SERVER KEY ID                           |
+-----------------------------------------+
| SENDER PUB KEY                          |
+-----------------------------------------+
| SHA256 CONTENT HASH (BEFORE ENCRYPTION) |                         ENCRYPTED_PACKET_DATA_SIZE
+-------------------------------------------------------------------+
| ENCRYPTED CONTENT OF THE PACKET                                   |
+-------------------------------------------------------------------+
```

**Server Key ID**

Is the sha256 of the serialized TL-object `PublicKey` of the server. This helps the server to identify which one of its public key were used in the generation of the __shared key__ through ECDH. Let's see this in a more details example:

Assume that the sender knows the public keys of receiver. Suppose the sender is using the server public key `Pub1`, which is a ed25519 Public Key. Given that is a ed25519 Public Key, this need to be serialized with the following TL definition:

```
pub.ed25519 key:int256 = PublicKey;
```

The serialization should include the [CRC32](https://datatracker.ietf.org/doc/html/rfc3385) of the TL definition, this kind of serialization are called __boxed__. In pseudo code this server key should be generated in this way:

```
SHA256(BOXED_SERIALIZER(PUBLIC_KEY_TL_OBJECT))
```

**Sender Public Key**

Given that the receiver of the packet also needs to generate the __shared secret__ in order to decrypt the data, the sender must include its own public key.

**Checksum of data before encryption**

The receiver will need to perform a validation of the data integrity it just decrypted, for this purpose the sender should include:

```
SHA256(UNENCRYPTED_DATA)
```

**Encrypted content**

The last part is the encrypted content, which as previously specified should be a TL serialization of `adnl.packetContent`. A full example will be provided later.

### Channel

When a sender will be exchanging several messages with the receiver, keeping the previously described format for all the messages doesn't makes sense given that contains redundant information like the `sender public key` which was known from the first message. In order to simplify this, ADNL use a `channel` mechanism, which will allow peers to exchange subsequents messages after the initial one to be simpler. The flow and idea is simple: 

1. For the creation of the channel, sender will need to generate a key pair of public and private key. Let's call it, `senderChannelPubKey` and `senderChannelPrivKey`. 

2. In the first message, on the field `messages` the sender includes a `adnl.createChannel` message. Which TL definition is the following:

```
adnl.message.createChannel key:int256 date:int = adnl.Message;
``` 

Reading the TL definition you can notice that a `key:int256` is included, this will be a `senderChannelPubKey` that we generated on our previous step. This along with the other messages to be sent in this first exchange, will be serialized and sent to receiver peer in the format we described previously.

3. As a response from the receiver, we should receive a `confirmChannel` message, which TL definition is the following:

```
adnl.message.confirmChannel key:int256 peer_key:int256 date:int = adnl.Message;
```

This message confirm that the peer receiver agree on the creation of the channel, and provide us with a `key:int256` which is `receiverPubKey` and `peer_key:int256` which is `ourPubKey`. These keys are necessary in order to create a __shared secret key__ as the one we use for the encryption of the first packet, but this time with the channel keys. To be more specific, sender creates its __shared secret__ with `senderPrivKey` and `receiverPubKey`, and receiver creates its __shared secret__ with `receiverPrivKey` and `senderPubKey`. This __shared secret__ is used for encryption and decryption.

4. Having the __shared secret__, both peers need to make 2 keys from it, one for `encrypting outgoing message` and another for decrypting `incomming messages`. This is made by using the __shared secret__ and the __reversed shared secret__. For example:

```
Shared secret: ABCD

Encryption key of outgoing messages : ABCD
Decryption of incomming messages: DCBA
```

Now we need some kind of coordination between the peers in order to know which of this two keys are been used for encryption and decryption on each peer. The coordination for this is done by making a numerical comparison between peers ids. For example:

```
SHARED SECRET: ABCD

PEERA_ID < PEERB_ID:
  FOR PEERA WE HAVE:
    ENCRYPTION KEY: ABCD
    DECRYPTION KEY: DCBA
  FOR PEERB WE HAVE:
    ENCRYPTION KEY: DCBA
    DECRYPTION KEY: ABCD

PEERA_ID > PEERB_ID:
  FOR PEERA WE HAVE:
    ENCRYPTION KEY: DCBA
    DECRYPTION KEY: ABCD
  FOR PEERB WE HAVE:
    ENCRYPTION KEY: ABCD
    DECRYPTION KEY: DCBA

PEERA_ID == PEERB_ID:
  FOR BOTH PEERS:
    ENCRYPTION: ABCD
    DECRYPTION: ABCD
```

An example in code can be found in [AdnlChannel::create](https://github.com/ton-blockchain/ton/blob/140320b0dbe0bdd9fd954b6633a3677acc75a8e6/adnl/adnl-channel.cpp#L30).

5. From now on sender and receiver had stablished a `channel` on which they can communicate in a more simplistic format.

#### Channel data format

The format of the data sent on a `channel` doesn't need to include the sender public key, also as a first 32-bytes peers will include an `ENCRYPTIOIN KEY ID`.

```
0                                         31
+-----------------------------------------+
| ENCRYPTION KEY ID                       |
+-----------------------------------------+
| SHA256 CONTENT HASH (BEFORE ENCRYPTION) |                         ENCRYPTED_PACKET_DATA_SIZE
+-------------------------------------------------------------------+
| ENCRYPTED CONTENT OF THE PACKET                                   |
+-------------------------------------------------------------------+
```

**Encryption key id**

Sender outgoing encryption key id, `SHA256(BOXED_SERIALIZED(AES_PUBLICKEY_TL_OBJECT))`.

**Content of packet**

The content of the packet follows as well a `adnl.packetContent`, but way more simplified including the following fields:

| Field name | flag byte position | type | description |
|------------|--------------------|------|-------------|
|rand1       | _ | bytes| random 7 or 15 bytes, why 7 or 15? No idea |
| flags | _ | int | flags marks which fields of the TL-object are present |
| message | 2 | adnl.Message | a single unit of [adnl.Message](https://github.com/ton-blockchain/ton/blob/140320b0dbe0bdd9fd954b6633a3677acc75a8e6/tl/generate/scheme/ton_api.tl#L130) checkout differents types on TL definition |
| seqno | 6 | long | sequence number of the packet, in case the receiver already proccessed a packet with this seqno, the packet will be dropped |
| confirm_seqno | 7 | long | latest confirmed sequence number, if confirm_seqno > out_seqno in the receiver node the packet will be dropped |
| rand2 | _ | bytes |  random 7 or 15 bytes |

A more detailed example can be found in the [official documentaion](https://docs.ton.org/develop/network/adnl-udp#communication-in-a-channel), and I'll provide one with code here as well later.

### Other message types
