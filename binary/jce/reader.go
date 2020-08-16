package jce

import (
	"bytes"
	"math"
	"reflect"
)

type Reader struct {
	buf  *bytes.Reader
	data []byte
}

type HeadData struct {
	Type byte
	Tag  int
}

func NewJceReader(data []byte) *Reader {
	buf := bytes.NewReader(data)
	return &Reader{buf: buf, data: data}
}

func (r *Reader) readHead() (hd *HeadData, l int32) {
	hd = &HeadData{}
	b, _ := r.buf.ReadByte()
	hd.Type = b & 0xF
	hd.Tag = (int(b) & 0xF0) >> 4
	if hd.Tag == 15 {
		b, _ = r.buf.ReadByte()
		hd.Tag = int(b) & 0xFF
		return hd, 2
	}
	return hd, 1
}

func (r *Reader) peekHead() (hd *HeadData, l int32) {
	offset := r.buf.Size() - int64(r.buf.Len())
	n := NewJceReader(r.data[offset:])
	return n.readHead()
}

func (r *Reader) skip(l int) {
	r.readBytes(l)
}

func (r *Reader) skipField(t byte) {
	switch t {
	case 0:
		r.skip(1)
	case 1:
		r.skip(2)
	case 2, 4:
		r.skip(4)
	case 3, 5:
		r.skip(8)
	case 6:
		b, _ := r.buf.ReadByte()
		r.skip(int(b))
	case 7:
		r.skip(int(r.readInt32()))
	case 8:
		s := r.ReadInt32(0)
		for i := 0; i < int(s)*2; i++ {
			r.skipNextField()
		}
	case 9:
		s := r.ReadInt32(0)
		for i := 0; i < int(s); i++ {
			r.skipNextField()
		}
	case 13:
		r.readHead()
		s := r.ReadInt32(0)
		r.skip(int(s))
	case 10:
		r.skipToStructEnd()
	}
}

func (r *Reader) skipNextField() {
	hd, _ := r.readHead()
	r.skipField(hd.Type)
}

func (r *Reader) SkipField(c int) {
	for i := 0; i < c; i++ {
		r.skipNextField()
	}
}

func (r *Reader) readBytes(len int) []byte {
	b := make([]byte, len)
	_, err := r.buf.Read(b)
	if err != nil {
		panic(err)
	}
	return b
}

func (r *Reader) readByte() byte {
	return r.readBytes(1)[0]
}

func (r *Reader) readUInt16() uint16 {
	f, _ := r.buf.ReadByte()
	s, err := r.buf.ReadByte()
	if err != nil {
		panic(err)
	}
	return uint16((int32(f) << 8) + int32(s))
}

func (r *Reader) readInt32() int32 {
	b := r.readBytes(4)
	return (int32(b[0]) << 24) | (int32(b[1]) << 16) | (int32(b[2]) << 8) | int32(b[3])
}

func (r *Reader) readInt64() int64 {
	b := r.readBytes(8)
	return (int64(b[0]) << 56) | (int64(b[1]) << 48) | (int64(b[2]) << 40) | (int64(b[3]) << 32) | (int64(b[4]) << 24) | (int64(b[5]) << 16) | (int64(b[6]) << 8) | int64(b[7])
}

func (r *Reader) readFloat32() float32 {
	b := r.readInt32()
	return math.Float32frombits(uint32(b))
}

func (r *Reader) readFloat64() float64 {
	b := r.readInt64()
	return math.Float64frombits(uint64(b))
}

func (r *Reader) skipToTag(tag int) bool {
	for {
		hd, l := r.peekHead()
		if tag <= hd.Tag || hd.Type == 11 {
			return tag == hd.Tag
		}
		r.skip(int(l))
		r.skipField(hd.Type)
	}
}

func (r *Reader) skipToStructEnd() {
	for {
		hd, _ := r.readHead()
		r.skipField(hd.Type)
		if hd.Type == 11 {
			return
		}
	}
}

func (r *Reader) ReadByte(tag int) byte {
	if !r.skipToTag(tag) {
		return 0
	}
	hd, _ := r.readHead()
	switch hd.Type {
	case 12:
		return 0
	case 0:
		return r.readByte()
	default:
		return 0
	}
}

func (r *Reader) ReadBool(tag int) bool {
	return r.ReadByte(tag) != 0
}

func (r *Reader) ReadInt16(tag int) int16 {
	if !r.skipToTag(tag) {
		return 0
	}
	hd, _ := r.readHead()
	switch hd.Type {
	case 12:
		return 0
	case 0:
		return int16(r.readByte())
	case 1:
		return int16(r.readUInt16())
	default:
		return 0
	}
}

func (r *Reader) ReadInt32(tag int) int32 {
	if !r.skipToTag(tag) {
		return 0
	}
	hd, _ := r.readHead()
	switch hd.Type {
	case 12:
		return 0
	case 0:
		return int32(r.readByte())
	case 1:
		return int32(r.readUInt16())
	case 2:
		return r.readInt32()
	default:
		return 0
	}
}

func (r *Reader) ReadInt64(tag int) int64 {
	if !r.skipToTag(tag) {
		return 0
	}
	hd, _ := r.readHead()
	switch hd.Type {
	case 12:
		return 0
	case 0:
		return int64(r.readByte())
	case 1:
		return int64(int16(r.readUInt16()))
	case 2:
		return int64(r.readInt32())
	case 3:
		return r.readInt64()
	default:
		return 0
	}
}

func (r *Reader) ReadFloat32(tag int) float32 {
	if !r.skipToTag(tag) {
		return 0
	}
	hd, _ := r.readHead()
	switch hd.Type {
	case 12:
		return 0
	case 4:
		return r.readFloat32()
	default:
		return 0
	}
}

func (r *Reader) ReadFloat64(tag int) float64 {
	if !r.skipToTag(tag) {
		return 0
	}
	hd, _ := r.readHead()
	switch hd.Type {
	case 12:
		return 0
	case 4:
		return float64(r.readFloat32())
	case 5:
		return r.readFloat64()
	default:
		return 0
	}
}

func (r *Reader) ReadString(tag int) string {
	if !r.skipToTag(tag) {
		return ""
	}
	hd, _ := r.readHead()
	switch hd.Type {
	case 6:
		return string(r.readBytes(int(r.readByte())))
	case 7:
		return string(r.readBytes(int(r.readInt32())))
	default:
		return ""
	}
}

// ReadAny Read any type via tag, unsupported JceStruct
func (r *Reader) ReadAny(tag int) interface{} {
	if !r.skipToTag(tag) {
		return nil
	}
	hd, _ := r.readHead()
	switch hd.Type {
	case 0:
		return r.readByte()
	case 1:
		return r.readUInt16()
	case 2:
		return r.readInt32()
	case 3:
		return r.readInt64()
	case 4:
		return r.readFloat32()
	case 5:
		return r.readFloat64()
	case 6:
		return string(r.readBytes(int(r.readByte())))
	case 7:
		return string(r.readBytes(int(r.readInt32())))
	case 8:
		s := r.ReadInt32(0)
		m := make(map[interface{}]interface{})
		for i := 0; i < int(s); i++ {
			m[r.ReadAny(0)] = r.ReadAny(1)
		}
		return m
	case 9:
		var sl []interface{}
		s := r.ReadInt32(0)
		for i := 0; i < int(s); i++ {
			sl = append(sl, r.ReadAny(0))
		}
		return sl
	case 12:
		return 0
	case 13:
		r.readHead()
		return r.readBytes(int(r.ReadInt32(0)))
	default:
		return nil
	}
}

func (r *Reader) ReadMapF(tag int, f func(interface{}, interface{})) {
	if !r.skipToTag(tag) {
		return
	}
	r.readHead()
	s := r.ReadInt32(0)
	for i := 0; i < int(s); i++ {
		k := r.ReadAny(0)
		v := r.ReadAny(1)
		if k != nil {
			f(k, v)
		}
	}
}

func (r *Reader) readObject(t reflect.Type, tag int) reflect.Value {
	switch t.Kind() {
	case reflect.Int, reflect.Int16, reflect.Int32, reflect.Int64:
		var i int64
		r.ReadObject(&i, tag)
		return reflect.ValueOf(i)
	case reflect.String:
		var s string
		r.ReadObject(&s, tag)
		return reflect.ValueOf(s)
	case reflect.Slice:
		s := reflect.New(t.Elem()).Interface().(Struct)
		r.readHead()
		s.ReadFrom(r)
		r.skipToStructEnd()
		return reflect.ValueOf(s).Elem()
	}
	return reflect.ValueOf(nil)
}

func (r *Reader) ReadSlice(i interface{}, tag int) {
	t := reflect.TypeOf(i)
	v := reflect.ValueOf(i).Elem()
	if t.Kind() != reflect.Ptr || t.Elem().Kind() != reflect.Slice {
		return
	}
	if v.IsNil() {
		return
	}
	if !r.skipToTag(tag) {
		return
	}
	hd, _ := r.readHead()
	if hd.Type == 9 {
		s := r.ReadInt32(0)
		for i := 0; i < int(s); i++ {
			val := r.readObject(t.Elem(), 0)
			v.Set(reflect.Append(v, val))
		}
	}
	if hd.Type == 13 {
		r.readHead()
		arr := r.readBytes(int(r.ReadInt32(0)))
		for _, b := range arr {
			v.Set(reflect.Append(v, reflect.ValueOf(b)))
		}
	}
}

func (r *Reader) ReadObject(i interface{}, tag int) {
	va := reflect.ValueOf(i)
	if va.Kind() != reflect.Ptr || va.IsNil() {
		return
	}
	switch o := i.(type) {
	case *byte:
		*o = r.ReadByte(tag)
	case *bool:
		*o = r.ReadBool(tag)
	case *int16:
		*o = r.ReadInt16(tag)
	case *int:
		*o = int(r.ReadInt32(tag))
	case *int32:
		*o = r.ReadInt32(tag)
	case *int64:
		*o = r.ReadInt64(tag)
	case *float32:
		*o = r.ReadFloat32(tag)
	case *float64:
		*o = r.ReadFloat64(tag)
	case *string:
		*o = r.ReadString(tag)
	case Struct:
		o.ReadFrom(r)
	}
}

func (r *Reader) ReadAvailable() []byte {
	return r.readBytes(r.buf.Len())
}
