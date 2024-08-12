package config

import (
	"encoding/json"
	"io"
	"net/http"
)

type Config struct {
	Type        string             `json:"@type"`
	Dht         DhtConfig          `json:"dht"`
	Liteservers []LiteserverConfig `json:"liteservers"`
	Validator   ValidatorConfig    `json:"validator"`
}

type ValidatorConfig struct {
	Type      string           `json:"@type"`
	ZeroState ZeroStateConfig  `json:"zero_state"`
	InitBlock InitBlockConfig  `json:"init_block"`
	Hardforks []HardforkConfig `json:"hardforks"`
}

type ZeroStateConfig struct {
	Workchain int    `json:"workchain"`
	Shard     int64  `json:"shard"`
	Seqno     int    `json:"seqno"`
	RootHash  string `json:"root_hash"`
	FileHash  string `json:"file_hash"`
}

type InitBlockConfig struct {
	RootHash  string `json:"root_hash"`
	Seqno     int    `json:"seqno"`
	FileHash  string `json:"file_hash"`
	Workchain int    `json:"workchain"`
	Shard     int64  `json:"shard"`
}

type HardforkConfig struct {
	FileHash  string `json:"file_hash"`
	Seqno     int    `json:"seqno"`
	RootHash  string `json:"root_hash"`
	Workchain int    `json:"workchain"`
	Shard     int64  `json:"shard"`
}

type LiteserverConfig struct {
	IP   int `json:"ip"`
	Port int `json:"port"`
	ID   ID  `json:"id"`
}

type ID struct {
	Type string `json:"@type"`
	Key  string `json:"key"`
}

type DhtConfig struct {
	Type        string            `json:"@type"`
	K           int               `json:"k"`
	A           int               `json:"a"`
	StaticNodes StaticNodesConfig `json:"static_nodes"`
}

type StaticNodesConfig struct {
	Type  string       `json:"@type"`
	Nodes []NodeConfig `json:"nodes"`
}

type NodeConfig struct {
	Type      string      `json:"@type"`
	ID        ID          `json:"id"`
	AddrList  AddressList `json:"addr_list"`
	Version   int         `json:"version"`
	Signature string      `json:"signature"`
}

type Address struct {
	Type string `json:"@type"`
	IP   int    `json:"ip"`
	Port int    `json:"port"`
}

type AddressList struct {
	Type       string    `json:"@type"`
	Addrs      []Address `json:"addrs"`
	Version    int       `json:"version"`
	ReinitDate int       `json:"reinit_date"`
	Priority   int       `json:"priority"`
	ExpireAt   int       `json:"expire_at"`
}

func LoadConfig() (*Config, error) {
	url := "https://ton-blockchain.github.io/global.config.json"
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var config Config
	err = json.Unmarshal(b, &config)
	if err != nil {
		return nil, err
	}

	return &config, nil
}
