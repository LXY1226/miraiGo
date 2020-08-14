package binary

import (
	"encoding/binary"
)

type Writer []byte

func NewWriter() *Writer {
	//b := make([]byte, 64)[:0]
	return (*Writer)(&[]byte{})
}

func NewWriterF(f func(writer *Writer)) []byte {
	w := NewWriter()
	f(w)
	return w.Bytes()
}

func (w *Writer) Write(b []byte) {
	*w = append(*w, b...)
}

func (w *Writer) WriteByte(b byte) {
	*w = append(*w, b)
}

func (w *Writer) WriteUInt16(v uint16) {
	*w = append(*w, []byte{0, 0}...)
	binary.BigEndian.PutUint16((*w)[len(*w)-2:], v)
}

func (w *Writer) WriteUInt32(v uint32) {
	*w = append(*w, []byte{0, 0, 0, 0}...)
	binary.BigEndian.PutUint32((*w)[len(*w)-4:], v)
}

func (w *Writer) WriteUInt64(v uint64) {
	*w = append(*w, []byte{0, 0, 0, 0, 0, 0, 0, 0}...)
	binary.BigEndian.PutUint64((*w)[len(*w)-8:], v)
}

func (w *Writer) WriteString(v string) {
	w.WriteUInt32(uint32(len(v) + 4))
	*w = append(*w, v...)
}

func (w *Writer) WriteStringShort(v string) {
	w.WriteTlv([]byte(v))
}

func (w *Writer) WriteBool(b bool) {
	if b {
		w.WriteByte(0x01)
	} else {
		w.WriteByte(0x00)
	}
}

func (w *Writer) EncryptAndWrite(key []byte, data []byte) {
	tea := NewTeaCipher(key)
	ed := tea.Encrypt(data)
	w.Write(ed)
}

func (w *Writer) WriteIntLvPacket(f func(writer *Writer)) {
	l := len(*w)
	*w = append(*w, []byte{0, 0, 0, 0}...)
	f(w)
	binary.BigEndian.PutUint32((*w)[l:], uint32(len(*w)-l))
}

func (w *Writer) WriteUniPacket(commandName string, sessionId, extraData, body []byte) {
	w.WriteIntLvPacket(func(w *Writer) {
		w.WriteString(commandName)
		w.WriteUInt32(8)
		w.Write(sessionId)
		if len(extraData) == 0 {
			w.WriteUInt32(0x04)
		} else {
			w.WriteUInt32(uint32(len(extraData) + 4))
			w.Write(extraData)
		}
	})
	w.WriteIntLvPacket(func(w *Writer) {
		w.Write(body)
	})
}

func (w *Writer) WriteTlv(data []byte) {
	w.WriteUInt16(uint16(len(data)))
	w.Write(data)
}

func (w *Writer) WriteTlvLimitedSize(data []byte, limit int) {
	if len(data) < limit {
		limit = len(data)
	}
	w.WriteTlv(data[:limit])
}

func (w *Writer) Bytes() []byte {
	//log.Output(3, fmt.Sprintf("Packet %d/%d", len(*w), cap(*w)))
	return *w
}
