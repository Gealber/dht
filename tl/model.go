package tl

import (
	"net"
)

const (
	TLCreateChannel     = "adnl.message.createChannel key:int256 date:int = adnl.Message"
	TLSignedAddressList = "dht.getSignedAddressList = dht.Node"
	TLMessageQuery      = "adnl.message.query query_id:int256 query:bytes = adnl.Message"
	TLAddressUDP        = "adnl.address.udp ip:int port:int = adnl.Address"
	TLAddressList       = "adnl.addressList addrs:(vector adnl.Address) version:int reinit_date:int priority:int expire_at:int = adnl.AddressList"
	TLPublicKeyEd25519  = "pub.ed25519 key:int256 = PublicKey"
	TLPublicKeyAES      = "pub.aes key:int256 = PublicKey"
	TLPacketContents    = `adnl.packetContents rand1:bytes flags:# from:flags.0?PublicKey from_short:flags.1?adnl.id.short message:flags.2?adnl.Message messages:flags.3?(vector adnl.Message) address:flags.4?adnl.addressList priority_address:flags.5?adnl.addressList seqno:flags.6?long confirm_seqno:flags.7?long recv_addr_list_version:flags.8?int recv_priority_addr_list_version:flags.9?int reinit_date:flags.10?int dst_reinit_date:flags.10?int signature:flags.11?bytes rand2:bytes = adnl.PacketContents`
	TLPing              = "adnl.ping value:long = adnl.Pong"
	TLPong              = "dht.pong random_id:long = dht.Pong;"
)

var (
	DefaultTLModel = []ModelRegister{
		{T: AdnlMessageCreateChannel{}, Def: TLCreateChannel},
		{T: GetSignedAddressList{}, Def: TLSignedAddressList},
		{T: Query{}, Def: TLMessageQuery},
		{T: AdnlAddressUDP{}, Def: TLAddressUDP},
		{T: AdnlAddressList{}, Def: TLAddressList},
		{T: PublicKeyED25519{}, Def: TLPublicKeyEd25519},
		{T: PublicKeyAES{}, Def: TLPublicKeyAES},
		{T: AdnlPacketContent{}, Def: TLPacketContents},
		{T: Ping{}, Def: TLPing},
		{T: Pong{}, Def: TLPong},
	}
)

type Ping struct {
	Value int64 `tl:"long"`
}

type Pong struct {
	RandomID int64 `tl:"long"`
}

type GetSignedAddressList struct{}

type Query struct {
	QueryID []byte `tl:"int256"`
	Query   []byte `tl:"bytes"`
}

type AdnlAddressList struct {
	Addresses  []AdnlAddressUDP `tl:"vector struct boxed"`
	Version    int64            `tl:"int"`
	ReinitDate int64            `tl:"int"`
	Priority   int64            `tl:"int"`
	ExpireAt   int64            `tl:"int"`
}

type AdnlAddressUDP struct {
	IP   net.IP `tl:"int"`
	Port int32  `tl:"int"`
}

// Public keys definitions
type PublicKeyUnenc struct {
	Data []byte `tl:"bytes"`
}

type PublicKeyED25519 struct {
	Key []byte `tl:"int256"`
}

type PublicKeyAES struct {
	Key []byte `tl:"int256"`
}

type PublicKeyOverlay struct {
	Name []byte `tl:"bytes"`
}

type AdnlPacketContent struct {
	Rand1                       []byte           `tl:"bytes"`
	Flags                       uint32           `tl:"flags"`
	From                        PublicKeyED25519 `tl:"?0 PublicKey"`
	FromIDShort                 []byte           `tl:"?1 adnl.id.short"`
	Message                     any              `tl:"?2 adnl.Message"`
	Messages                    []any            `tl:"?3 vector adnl.Message"`
	AddressList                 AdnlAddressList  `tl:"?4 adnl.addressList"`
	PriorityAddressList         AdnlAddressList  `tl:"?5 adnl.addressList"`
	Seqno                       int64            `tl:"?6 long"`
	ConfirmSeqno                int64            `tl:"?7 long"`
	RecvAddrListVersion         int64            `tl:"?7 int"`
	RecvPriorityAddrListVersion int64            `tl:"?9 int"`
	ReinitDate                  int64            `tl:"?10 int"`
	DstReinitDate               int64            `tl:"?10 int"`
	Signature                   []byte           `tl:"?11 bytes"`
	Rand2                       []byte           `tl:"bytes"`
}

type AdnlTunnelPacketContents struct {
	Rand1      []byte `tl:"bytes"`
	Flags      uint32 `tl:"flags"`
	FromIP     int    `tl:"flags.0?int"`
	FromPort   int    `tl:"flags.0?int"`
	Message    []byte `tl:"flags.1?bytes"`
	Statistics []byte `tl:"flags.2?bytes"`
	Payment    []byte `tl:"flags.3?bytes"`
	Rand2      []byte `tl:"bytes"`
}

type AdnlMessageCreateChannel struct {
	Key  []byte `tl:"int256"`
	Date int64  `tl:"int"`
}

type AdnlMessageConfirmChannel struct {
	Key      []byte `tl:"int256"`
	PeerKKey []byte `tl:"int256"`
	Date     int64  `tl:"int"`
}

type AdnlMessageCustom struct {
	Data []byte `tl:"bytes"`
}

type AdnlMessageQuery struct {
	QueryID []byte `tl:"int256"`
	Query   []byte `tl:"bytes"`
}

type AdnlMessageAnswer struct {
	QueryID []byte `tl:"int256"`
	Answer  []byte `tl:"bytes"`
}

type AdnlMessagePart struct {
	Hash      []byte `tl:"int256"`
	TotalSize int    `tl:"int"`
	Offset    int    `tl:"int"`
	Data      []byte `tl:"bytes"`
}
