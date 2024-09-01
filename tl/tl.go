package tl

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"log"
	"math/big"
	"reflect"
	"strconv"
	"strings"
)

var (
	BoolTrueHexID  = "b5757299"
	BoolFalseHexID = "379779bc"
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

type TLHandler struct {
	// map to keep registers of TL definition
	// <go type %T,full definition> map
	register map[string]string
	// flagsRegister keeps track of flags set on models
	flagsRegister map[string]int
}

func New() *TLHandler {
	return &TLHandler{
		register:      make(map[string]string),
		flagsRegister: make(map[string]int),
	}
}

func (t *TLHandler) Register(models []ModelRegister) {
	for _, m := range models {
		t.register[fmt.Sprintf("%T", m.T)] = m.Def
	}
}

// Serialize a struct with `tl` tags defined
// into it's binary representation. In case boxed is true,
// obj MUST be previously registered with Register method.
func (t *TLHandler) Serialize(obj any, boxed bool) ([]byte, error) {
	data := make([]byte, 0)
	if boxed {
		def, ok := t.register[fmt.Sprintf("%T", obj)]
		if !ok {
			return nil, fmt.Errorf("model needs to be previously registered if boxed is true: %T", obj)
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

func (t *TLHandler) serializeField(st reflect.Type, v reflect.Value, idx int) ([]byte, error) {
	field := st.Field(idx)

	tagVal := field.Tag.Get("tl")
	if tagVal == "" || tagVal == "-" {
		return nil, nil
	}

	fieldKind := v.Field(idx).Kind()
	fieldValue := v.Field(idx)

	if tagVal == "flags" {
		buff := make([]byte, 4)
		if fieldKind >= reflect.Int && fieldKind <= reflect.Int64 {
			binary.LittleEndian.PutUint32(buff, uint32(fieldValue.Int()))
			t.flagsRegister[st.String()] = int(fieldValue.Int())
		} else if fieldKind >= reflect.Uint && fieldKind <= reflect.Uint64 {
			binary.LittleEndian.PutUint32(buff, uint32(fieldValue.Uint()))
			t.flagsRegister[st.String()] = int(fieldValue.Uint())
		} else {
			return nil, errors.New("invalid field type for 'flags'")
		}

		return buff, nil
	}

	if tagVal[0] == '?' {
		if len(tagVal) <= 2 {
			return nil, errors.New("'?' should be followed by bit position and type")
		}

		spaceIdx := strings.Index(tagVal, " ")
		if spaceIdx == -1 {
			return nil, errors.New("'?' definition should be separated by space, for example '?0 int'")
		}

		bitPos, err := strconv.Atoi(tagVal[1:spaceIdx])
		if err != nil {
			return nil, err
		}

		// 'flags' is a 32-bit integer
		if bitPos < 0 || bitPos > 31 {
			return nil, errors.New("invalid bit position for '?' definition")
		}

		// check if this bit in flag is set
		flags, ok := t.flagsRegister[st.String()]
		if !ok {
			return nil, errors.New("'flags' should be previously defined")
		}

		// if bit in bitPos is not set in flags value, we don't process this field
		if flags&(1<<bitPos) == 0 {
			return nil, nil
		}

		// make part after ' ' space the tagVal
		if len(tagVal)-1 == spaceIdx {
			return nil, errors.New("tag value cannot end with space")
		}

		tagVal = tagVal[spaceIdx+1:]
	}

	if strings.HasPrefix(tagVal, "vector") {
		// parse second part of tagVal expected to be 'vector T'
		spaceIdx := strings.Index(tagVal, " ")
		if spaceIdx == -1 {
			return nil, errors.New("'vector' definition should be followed by space and TL type, for example 'vector int'")
		}

		// check the fieldKind is slice
		if fieldKind != reflect.Slice {
			return nil, errors.New("'vector' definition should be a slice")
		}

		// make part after ' ' space the tagVal
		if len(tagVal)-1 == spaceIdx {
			return nil, errors.New("tag value cannot end with space")
		}

		tagVal = tagVal[spaceIdx+1:]
		buff := make([]byte, 0)

		// setting size of slice first
		tmp := make([]byte, 4)
		binary.LittleEndian.PutUint32(tmp, uint32(fieldValue.Len()))
		buff = append(buff, tmp...)

		// iterate over elements in slice and
		size := fieldValue.Len()
		for i := 0; i < size; i++ {
			fIdx := fieldValue.Index(i)
			// parse element
			subBuff, err := t.serializeSimpleField(fIdx.Kind(), fIdx, tagVal)
			if err != nil {
				return nil, err
			}

			buff = append(buff, subBuff...)
		}

		return buff, nil
	}

	return t.serializeSimpleField(fieldKind, fieldValue, tagVal)
}

func (t *TLHandler) serializeSimpleField(fieldKind reflect.Kind, fieldValue reflect.Value, tagVal string) ([]byte, error) {
	switch tagVal {
	case "int":
		buff := make([]byte, 4)
		if fieldKind >= reflect.Int && fieldKind <= reflect.Int64 {
			binary.LittleEndian.PutUint32(buff, uint32(fieldValue.Int()))
		} else if fieldKind >= reflect.Uint && fieldKind <= reflect.Uint64 {
			binary.LittleEndian.PutUint32(buff, uint32(fieldValue.Uint()))
		} else {
			return nil, errors.New("invalid field type for TL type 'int'")
		}

		return buff, nil
	case "long":
		buff := make([]byte, 8)
		if fieldKind >= reflect.Int && fieldKind <= reflect.Int64 {
			binary.LittleEndian.PutUint32(buff, uint32(fieldValue.Int()))
		} else if fieldKind >= reflect.Uint && fieldKind <= reflect.Uint64 {
			binary.LittleEndian.PutUint32(buff, uint32(fieldValue.Uint()))
		} else {
			return nil, errors.New("invalid field type for TL type 'long'")
		}

		return buff, nil
	// case "double":
	// TODO: to implement double
	case "string":
		if fieldKind == reflect.String {
			return ToBytes([]byte(fieldValue.String())), nil
		} else {
			return nil, errors.New("invalid field type for TL type 'string'")
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
		} else {
			return nil, errors.New("invalid field type for TL type 'bool'")
		}
	case "bytes":
		if fieldKind == reflect.Slice {
			return ToBytes(fieldValue.Bytes()), nil
		} else {
			return nil, errors.New("invalid field type for TL type 'bytes'")
		}
	default:
		if fieldKind == reflect.Interface && !fieldValue.IsNil() {
			// try to check the underlaying type of it
			fV := fieldValue.Elem()
			fK := fV.Kind()

			return t.serializeSimpleField(fK, fV, tagVal)
		}

		// in case is a custom type, check if is previously registered
		if tlDef, ok := t.register[fieldValue.Type().String()]; ok {
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
}

// Parse data into obj, is assummed obj TL definition was already registered with Register method, and data provided was serialized in the order the TL definition states.
func (t *TLHandler) Parse(data []byte, obj any, boxed bool) error {
	if len(data) == 0 {
		return errors.New("empty data")
	}

	objV := reflect.ValueOf(obj)
	if objV.Kind() != reflect.Pointer || objV.IsNil() {
		return fmt.Errorf("v should be a pointer and not nil")
	}

	_, err := t.parse(data, objV, boxed)

	return err
}

// TODO: refactor to make it a smaller method
func (t *TLHandler) parse(data []byte, objValue reflect.Value, boxed bool) (int, error) {
	pos := 0
	flags := 0xffff // assuming all the bits are set
	// check if schemeID correspond to one registered
	registerKey := fmt.Sprintf("%s", reflect.Indirect(objValue).Type().String())
	tlDef, ok := t.register[registerKey]
	if !ok {
		return pos, fmt.Errorf("obj %s not registered", reflect.Indirect(objValue).Type().String())
	}

	inOrderTs := extractTypes(tlDef)
	vt := objValue.Elem()

	if vt.NumField() != len(inOrderTs) {
		return pos, errors.New("number of fields in obj differs from types defined in TL definition")
	}

	if boxed {
		// parse the 4-bytes scheme id
		schemeID := data[:4]
		if hex.EncodeToString(schemeID) != SchemeID(tlDef) {
			return pos, errors.New("invalid scheme id according to tl definition registered, check if the tl definition is correct")
		}
		pos = 4
	}

	// TODO: this loops is assuming all fields are present, which is not correct
	for i, fieldT := range inOrderTs {
		fieldValue := vt.Field(i)
		fieldKind := fieldValue.Kind()

		if fieldT == "#" {
			if fieldKind < reflect.Int || fieldKind > reflect.Int64 {
				flags = int(fieldValue.Int())
			}
		}

		bitPos, tDef := extractBitPosition(fieldT)
		if bitPos != -1 {
			// flags is not set ignore processing of this field
			if (flags>>bitPos)&1 == 0 {
				continue
			}
			// otherwise
			fieldT = tDef
		}

		switch fieldT {
		case "int":
			n := binary.LittleEndian.Uint32(data[pos : pos+4])
			if fieldKind >= reflect.Int && fieldKind <= reflect.Int64 {
				fieldValue.SetInt(int64(n))
			} else if fieldKind >= reflect.Uint && fieldKind <= reflect.Uint64 {
				fieldValue.SetUint(uint64(n))
			} else {
				return pos, errors.New("unexpected field type for 'int' TL type")
			}
			pos += 4
		case "long":
			n := binary.LittleEndian.Uint32(data[pos : pos+8])
			if fieldKind >= reflect.Int && fieldKind <= reflect.Int64 {
				fieldValue.SetInt(int64(n))
			} else if fieldKind >= reflect.Uint && fieldKind <= reflect.Uint64 {
				fieldValue.SetUint(uint64(n))
			} else {
				return pos, errors.New("unexpected field type for 'int' TL type")
			}
			pos += 8
		case "double":
			// TODO: to implement
		case "string":
			if fieldKind != reflect.String {
				return pos, errors.New("invalid field type for 'string' TL type")
			}

			val, err := FromBytes(data[pos:])
			if err != nil {
				return pos, err
			}
			fieldValue.SetString(string(val))

			offset := func() int {
				var result int
				if len(val) < 0xFE {
					result = 1
				} else {
					result = 4
				}
				round := (len(val) + result) % 4

				if round != 0 {
					result += 4 - round
				}

				return result
			}()

			pos += len(val) + offset
		case "int256":
			b := data[pos : pos+32]
			if fieldKind == reflect.Slice {
				fieldValue.SetBytes(b)
			} else if v, ok := fieldValue.Interface().(*big.Int); ok {
				fieldValue.Set(reflect.ValueOf(v))
			} else {
				return pos, errors.New("only []byte and *big.Int can be used for int256")
			}

			pos += 32
		case "bool":
			if fieldKind != reflect.Bool {
				return pos, errors.New("invalid field type for 'bool' TL type")
			}

			boolTCrc32 := hex.EncodeToString(data[pos : pos+4])
			if boolTCrc32 == BoolTrueHexID {
				fieldValue.SetBool(true)
			} else if boolTCrc32 == BoolFalseHexID {
				fieldValue.SetBool(false)
			} else {
				return pos, errors.New("invalid Crc32 for TL Bool type")
			}

			pos += 4
		case "bytes":
			if fieldKind != reflect.Slice {
				return pos, errors.New("invalid field type for 'bytes' TL type")
			}

			val, err := FromBytes(data[pos:])
			if err != nil {
				return pos, err
			}

			fieldValue.SetBytes(val)

			offset := func() int {
				var result int
				if len(val) < 0xFE {
					result = 1
				} else {
					result = 4
				}
				round := (len(val) + result) % 4

				if round != 0 {
					result += 4 - round
				}

				return result
			}()

			pos += len(val) + offset
		default:
			if tlDef, ok := t.register[fieldValue.Type().String()]; ok {
				combinator, constructor := getCombinator(tlDef), getConstructor(tlDef)
				if fieldT != combinator && fieldT != constructor {
					return pos, errors.New("your tag definition doesn't correspond with the combinator or constructor in the registered definition")
				}
				boxed := fieldT == getCombinator(tlDef)
				// how many of remaining data correspond to this field type
				objField := reflect.New(fieldValue.Type())
				consumed, err := t.parse(data[pos:], objField, boxed)
				if err != nil {
					return pos, err
				}
				pos += consumed
			} else {
				log.Println("FIELD TYPE: ", fieldT)
				return pos, errors.New("unregistered custom type as field")
			}
		}
	}

	return pos, nil
}
