package tl

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"math/big"
	"reflect"
	"strings"
)

// Crc32 given an TL-scheme computes the crc32.
func Crc32(scheme string) uint32 {
	scheme = strings.ReplaceAll(scheme, "(", "")
	scheme = strings.ReplaceAll(scheme, ")", "")
	scheme = strings.ReplaceAll(scheme, ";", "")

	return crc32.ChecksumIEEE([]byte(scheme))
}

// SchemeID given an TL-scheme computes the TL-ID
// returning the hex representation of it.
func SchemeID(scheme string) string {
	id := Crc32(scheme)
	b := make([]byte, 4)

	binary.LittleEndian.PutUint32(b, id)

	return hex.EncodeToString(b)
}

type ModelRegister struct {
	// T is struct that we want to associated with TL definition Def
	T   any
	Def string
}

type Serializer struct {
	// map to keep registers of TL definition
	// <go type %T,full definition> map
	register map[string]string
}

func NewSerializer() *Serializer {
	return &Serializer{
		register: make(map[string]string),
	}
}

func (t *Serializer) Register(models []ModelRegister) {
	for _, m := range models {
		t.register[fmt.Sprintf("%T", m.T)] = m.Def
	}
}

// Serialize a struct with `tl` tags defined
// into it's binary representation. In case boxed is true,
// obj MUST be previously registered with Register method.
func (t *Serializer) Serialize(obj any, boxed bool) ([]byte, error) {
	data := make([]byte, 0)
	if boxed {
		def, ok := t.register[fmt.Sprintf("%T", obj)]
		if !ok {
			return nil, errors.New("model needs to be previously registered if boxed is true")
		}

		// append scheme id in data
		id, err := hex.DecodeString(SchemeID(def))
		if err != nil {
			return nil, err
		}

		data = append(data, id...)
	}

	// check each fields tag
	st := reflect.TypeOf(obj)
	v := reflect.ValueOf(obj)
	for i := 0; i < st.NumField(); i++ {
		d, err := t.serializeField(st, v, i)
		if err != nil {
			return nil, err
		}

		if len(d) == 0 {
			continue
		}

		data = append(data, d...)
	}

	return data, nil
}

func (t *Serializer) serializeField(st reflect.Type, v reflect.Value, idx int) ([]byte, error) {
	field := st.Field(idx)

	tagVal := field.Tag.Get("tl")
	if tagVal == "" || tagVal == "-" {
		return nil, nil
	}

	fieldKind := v.Field(idx).Kind()
	fieldValue := v.Field(idx)

	switch tagVal {
	case "int":
		buff := make([]byte, 4)
		if fieldKind >= reflect.Int && fieldKind <= reflect.Int64 {
			binary.LittleEndian.PutUint32(buff, uint32(fieldValue.Int()))
		} else if fieldKind >= reflect.Uint && fieldKind <= reflect.Uint64 {
			binary.LittleEndian.PutUint32(buff, uint32(fieldValue.Uint()))
		} else {
			return nil, nil
		}

		return buff, nil
	case "long":
		buff := make([]byte, 8)
		if fieldKind >= reflect.Int && fieldKind <= reflect.Int64 {
			binary.LittleEndian.PutUint32(buff, uint32(fieldValue.Int()))
		} else if fieldKind >= reflect.Uint && fieldKind <= reflect.Uint64 {
			binary.LittleEndian.PutUint32(buff, uint32(fieldValue.Uint()))
		} else {
			return nil, nil
		}

		return buff, nil
	case "double":
		// TODO: to implement double
	case "string":
		if fieldKind == reflect.String {
			return ToBytes([]byte(fieldValue.String())), nil
		}
	case "int256":
		var b []byte
		if fieldKind == reflect.Slice {
			// assuming were passed in little endian
			b = fieldValue.Bytes()
		} else if v, ok := fieldValue.Interface().(*big.Int); ok {
			b = v.Bytes()
		} else {
			return nil, errors.New("only []byte and *big.Int can be used for int256")
		}

		if len(b) == 0 {
			return make([]byte, 32), nil
		}

		if len(b) < 32 {
			buff := make([]byte, 32)
			copy(buff[32-len(b):], b)
			return buff, nil
		}

		if len(b) > 32 {
			return nil, errors.New("int256 bytes should be 32 bytes in size no more than that")
		}

		return b, nil
	case "bool":
		if fieldKind == reflect.Bool {
			buff := make([]byte, 4)
			if fieldValue.Bool() {
				binary.LittleEndian.PutUint32(buff, Crc32("boolTrue = Bool"))
			} else {
				binary.LittleEndian.PutUint32(buff, Crc32("boolFalse = Bool"))
			}

			return buff, nil
		}
	case "bytes":
		if fieldKind == reflect.Slice {
			return ToBytes(fieldValue.Bytes()), nil
		}
	default:
		// in case is a custom type, check if is previously registered
		if tlDef, ok := t.register[field.Type.String()]; ok {
			combinator, constructor := getCombinator(tlDef), getConstructor(tlDef)
			if tagVal != combinator && tagVal != constructor {
				return nil, errors.New("your tag definition doesn't correspond with the combinator or constructor in the registered definition")
			}
			// check if is explicit or not, according to
			// https://docs.ton.org/develop/data-formats/tl#non-obvious-serialization-rules
			boxed := tagVal == getCombinator(tlDef)
			return t.Serialize(fieldValue.Interface(), boxed)
		} else {
			return nil, errors.New("unregistered custom type as field")
		}
	}

	return nil, errors.New("unsupported serialization check fields 'tl' definition")
}
