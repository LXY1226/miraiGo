package jce

import (
	"bytes"
	goBinary "encoding/binary"
	"reflect"
	"strconv"
)

type Writer struct {
	buf *bytes.Buffer
}

func NewJceWriter() *Writer {
	return &Writer{buf: new(bytes.Buffer)}
}

func (w *Writer) writeHead(t byte, tag int) {
	if tag < 15 {
		b := byte(tag<<4) | t
		w.buf.WriteByte(b)
	} else if tag < 256 {
		b := 0xF0 | t
		w.buf.WriteByte(b)
		w.buf.WriteByte(byte(tag))
	}
}

func (w *Writer) WriteByte(b byte, tag int) {
	if b == 0 {
		w.writeHead(12, tag)
	} else {
		w.writeHead(0, tag)
		w.buf.WriteByte(b)
	}
}

func (w *Writer) WriteBool(b bool, tag int) {
	var by byte = 0
	if b {
		by = 1
	}
	w.WriteByte(by, tag)
}

func (w *Writer) WriteInt16(n int16, tag int) {
	if n >= -128 && n <= 127 {
		w.WriteByte(byte(n), tag)
		return
	}
	w.writeHead(1, tag)
	_ = goBinary.Write(w.buf, goBinary.BigEndian, n)
}

func (w *Writer) WriteInt32(n int32, tag int) {
	if n >= -32768 && n <= 32767 { // ? if ((n >= 32768) && (n <= 32767))
		w.WriteInt16(int16(n), tag)
		return
	}
	w.writeHead(2, tag)
	_ = goBinary.Write(w.buf, goBinary.BigEndian, n)
}

func (w *Writer) WriteInt64(n int64, tag int) {
	if n >= -2147483648 && n <= 2147483647 {
		w.WriteInt32(int32(n), tag)
		return
	}
	w.writeHead(3, tag)
	_ = goBinary.Write(w.buf, goBinary.BigEndian, n)
}

func (w *Writer) WriteFloat32(n float32, tag int) {
	w.writeHead(4, tag)
	_ = goBinary.Write(w.buf, goBinary.BigEndian, n)
}

func (w *Writer) WriteFloat64(n float64, tag int) {
	w.writeHead(5, tag)
	_ = goBinary.Write(w.buf, goBinary.BigEndian, n)
}

func (w *Writer) WriteString(s string, tag int) {
	by := []byte(s)
	if len(by) > 255 {
		w.writeHead(7, tag)
		_ = goBinary.Write(w.buf, goBinary.BigEndian, len(by))
		w.buf.Write(by)
		return
	}
	w.writeHead(6, tag)
	w.buf.WriteByte(byte(len(by)))
	w.buf.Write(by)
}

func (w *Writer) WriteBytes(l []byte, tag int) {
	w.writeHead(13, tag)
	w.writeHead(0, 0)
	w.WriteInt32(int32(len(l)), 0)
	w.buf.Write(l)
}

func (w *Writer) WriteInt64Slice(l []int64, tag int) {
	w.writeHead(9, tag)
	if len(l) == 0 {
		w.WriteInt32(0, 0)
		return
	}
	w.WriteInt32(int32(len(l)), 0)
	for _, v := range l {
		w.WriteInt64(v, 0)
	}
}

func (w *Writer) WriteJceStructSlice(l []Struct, tag int) {
	w.writeHead(9, tag)
	if len(l) == 0 {
		w.WriteInt32(0, 0)
		return
	}
	w.WriteInt32(int32(len(l)), 0)
	for _, v := range l {
		w.WriteJceStruct(v, 0)
	}
}

func (w *Writer) WriteMap(m interface{}, tag int) {
	if m == nil {
		w.writeHead(8, tag)
		w.WriteInt32(0, 0)
		return
	}
	va := reflect.ValueOf(m)
	if va.Kind() != reflect.Map {
		return
	}
	w.writeHead(8, tag)
	w.WriteInt32(int32(len(va.MapKeys())), 0)
	for _, k := range va.MapKeys() {
		v := va.MapIndex(k)
		w.WriteObject(k.Interface(), 0)
		w.WriteObject(v.Interface(), 1)
	}
}

func (w *Writer) WriteObject(i interface{}, tag int) {
	t := reflect.TypeOf(i)
	if t.Kind() == reflect.Map {
		w.WriteMap(i, tag)
		return
	}
	switch o := i.(type) {
	case byte:
		w.WriteByte(o, tag)
	case bool:
		w.WriteBool(o, tag)
	case int16:
		w.WriteInt16(o, tag)
	case int32:
		w.WriteInt32(o, tag)
	case int64:
		w.WriteInt64(o, tag)
	case float32:
		w.WriteFloat32(o, tag)
	case float64:
		w.WriteFloat64(o, tag)
	case string:
		w.WriteString(o, tag)
	case []byte:
		w.WriteBytes(o, tag)
	case []int64:
		w.WriteInt64Slice(o, tag)
	case Struct:
		w.WriteJceStruct(o, tag)
	case []Struct:
		w.WriteJceStructSlice(o, tag)
	}
}

func (w *Writer) WriteJceStructRaw(s Struct) {
	var (
		t = reflect.TypeOf(s).Elem()
		v = reflect.ValueOf(s).Elem()
	)
	for i := 0; i < t.NumField(); i++ {
		strId := t.Field(i).Tag.Get("jceId")
		if strId == "" {
			continue
		}
		id, err := strconv.Atoi(strId)
		if err != nil {
			continue
		}
		w.WriteObject(v.Field(i).Interface(), id)
	}
}

func (w *Writer) WriteJceStruct(s Struct, tag int) {
	w.writeHead(10, tag)
	w.WriteJceStructRaw(s)
	w.writeHead(11, 0)
}

func (w *Writer) Bytes() []byte {
	return w.buf.Bytes()
}
