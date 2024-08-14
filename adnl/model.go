package adnl

import (
	"crypto/ed25519"
	"net"

	"github.com/xssnick/tonutils-go/tl"
)

func init() {
	tl.Register(PublicKeyED25519{}, "pub.ed25519 key:int256 = PublicKey")
	tl.Register(List{}, "adnl.addressList addrs:(vector adnl.Address) version:int reinit_date:int priority:int expire_at:int = adnl.AddressList")
	tl.Register(CreateChannel{}, "adnl.message.createChannel key:int256 date:int = adnl.Message")
	tl.Register(GetSignedAddressList{}, "dht.getSignedAddressList = dht.Node")
	tl.Register(Query{}, "adnl.message.query query_id:int256 query:bytes = adnl.Message")
	tl.Register(PacketContent{}, "adnl.packetContents rand1:bytes flags:# "+
		"from:flags.0?PublicKey from_short:flags.1?adnl.id.short "+
		"message:flags.2?adnl.Message messages:flags.3?(vector adnl.Message) "+
		"address:flags.4?adnl.addressList priority_address:flags.5?adnl.addressList "+
		"seqno:flags.6?long confirm_seqno:flags.7?long recv_addr_list_version:flags.8?int "+
		"recv_priority_addr_list_version:flags.9?int reinit_date:flags.10?int "+
		"dst_reinit_date:flags.10?int signature:flags.11?bytes rand2:bytes = adnl.PacketContents")
}

type CreateChannel struct {
	Key  []byte `tl:"int256"`
	Date int64  `tl:"int"`
}

type GetSignedAddressList struct{}

type Query struct {
	QueryID []byte `tl:"int256"`
	Query   []byte `tl:"bytes"`
}

type List struct {
	Addresses  []*UDP `tl:"vector struct boxed"`
	Version    int32  `tl:"int"`
	ReinitDate int32  `tl:"int"`
	Priority   int32  `tl:"int"`
	ExpireAt   int32  `tl:"int"`
}

type UDP struct {
	IP   net.IP `tl:"int"`
	Port int32  `tl:"int"`
}

type PublicKeyED25519 struct {
	Key ed25519.PublicKey `tl:"int256"`
}

type PacketContent struct {
	Rand1                       []byte           `tl:"bytes"`
	Flags                       uint32           `tl:"flags"`
	From                        PublicKeyED25519 `tl:"?0 PublicKey"`
	FromIDShort                 []byte           `tl:"?1 adnl.id.short"`
	Message                     any              `tl:"?2 adnl.Message"`
	Messages                    []any            `tl:"?3 (vector adnl.Message)"`
	Address                     *List            `tl:"?4 adnl.addressList"`
	PriorityAddress             *List            `tl:"?5 adnl.addressList"`
	Seqno                       *int64           `tl:"?6 long"`
	ConfirmSeqno                *int64           `tl:"?7 long"`
	RecvAddrListVersion         *int32           `tl:"?7 int"`
	RecvPriorityAddrListVersion *int32           `tl:"?9 int"`
	ReinitDate                  *int32           `tl:"?10 int"`
	DstReinitDate               *int32           `tl:"?10 int"`
	Signature                   []byte           `tl:"?11 bytes"`
	Rand2                       []byte           `tl:"bytes"`
}