int ? = Int;
long ? = Long;
double ? = Double;
string ? = String;
object ? = Object;
function ? = Function;
bytes data:string = Bytes;
true = True;
boolTrue = Bool;
boolFalse = Bool;

int256 8*[ int ] = Int256;

---types---

pk.unenc data:bytes = PrivateKey;
pk.ed25519 key:int256 = PrivateKey;
pk.aes key:int256 = PrivateKey;
pk.overlay name:bytes = PrivateKey;

pub.unenc data:bytes = PublicKey;
pub.ed25519 key:int256 = PublicKey;
pub.aes key:int256 = PublicKey;
pub.overlay name:bytes = PublicKey;

---functions---
---types---
dht.node id:PublicKey addr_list:adnl.addressList version:int signature:bytes = dht.Node;
dht.nodes nodes:(vector dht.node) = dht.Nodes;

dht.key id:int256 name:bytes idx:int = dht.Key;

dht.updateRule.signature = dht.UpdateRule;
dht.updateRule.anybody = dht.UpdateRule;
dht.updateRule.overlayNodes = dht.UpdateRule;

dht.keyDescription key:dht.key id:PublicKey update_rule:dht.UpdateRule signature:bytes = dht.KeyDescription;

dht.value key:dht.keyDescription value:bytes ttl:int signature:bytes = dht.Value; 

dht.pong random_id:long = dht.Pong;

dht.valueNotFound nodes:dht.nodes = dht.ValueResult;
dht.valueFound value:dht.Value = dht.ValueResult;

---functions---

dht.ping random_id:long = dht.Pong;
dht.store value:dht.value = dht.Stored;
dht.findNode key:int256 k:int = dht.Nodes; 
dht.findValue key:int256 k:int = dht.ValueResult; 