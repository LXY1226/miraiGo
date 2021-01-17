// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: client/pb/oidb/oidb0xe5b.proto

package oidb

import (
	fmt "fmt"
	proto "github.com/gogo/protobuf/proto"
	io "io"
	math "math"
	math_bits "math/bits"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion3 // please upgrade the proto package

type LifeAchievementItem struct {
	AchievementId      uint32 `protobuf:"varint,1,opt,name=achievementId" json:"achievementId"`
	AchievementTitle   string `protobuf:"bytes,2,opt,name=achievementTitle" json:"achievementTitle"`
	AchievementIcon    string `protobuf:"bytes,3,opt,name=achievementIcon" json:"achievementIcon"`
	HasPraised         bool   `protobuf:"varint,4,opt,name=hasPraised" json:"hasPraised"`
	PraiseNum          uint32 `protobuf:"varint,5,opt,name=praiseNum" json:"praiseNum"`
	AchievementContent []byte `protobuf:"bytes,6,opt,name=achievementContent" json:"achievementContent"`
}

func (m *LifeAchievementItem) Reset()         { *m = LifeAchievementItem{} }
func (m *LifeAchievementItem) String() string { return proto.CompactTextString(m) }
func (*LifeAchievementItem) ProtoMessage()    {}
func (*LifeAchievementItem) Descriptor() ([]byte, []int) {
	return fileDescriptor_306a22bb1626016b, []int{0}
}
func (m *LifeAchievementItem) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *LifeAchievementItem) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_LifeAchievementItem.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *LifeAchievementItem) XXX_Merge(src proto.Message) {
	xxx_messageInfo_LifeAchievementItem.Merge(m, src)
}
func (m *LifeAchievementItem) XXX_Size() int {
	return m.Size()
}
func (m *LifeAchievementItem) XXX_DiscardUnknown() {
	xxx_messageInfo_LifeAchievementItem.DiscardUnknown(m)
}

var xxx_messageInfo_LifeAchievementItem proto.InternalMessageInfo

func (m *LifeAchievementItem) GetAchievementId() uint32 {
	if m != nil {
		return m.AchievementId
	}
	return 0
}

func (m *LifeAchievementItem) GetAchievementTitle() string {
	if m != nil {
		return m.AchievementTitle
	}
	return ""
}

func (m *LifeAchievementItem) GetAchievementIcon() string {
	if m != nil {
		return m.AchievementIcon
	}
	return ""
}

func (m *LifeAchievementItem) GetHasPraised() bool {
	if m != nil {
		return m.HasPraised
	}
	return false
}

func (m *LifeAchievementItem) GetPraiseNum() uint32 {
	if m != nil {
		return m.PraiseNum
	}
	return 0
}

func (m *LifeAchievementItem) GetAchievementContent() []byte {
	if m != nil {
		return m.AchievementContent
	}
	return nil
}

type DE5BReqBody struct {
	Uin                   uint64   `protobuf:"varint,1,opt,name=uin" json:"uin"`
	AchievementId         []uint32 `protobuf:"varint,2,rep,name=achievementId" json:"achievementId,omitempty"`
	MaxCount              uint32   `protobuf:"varint,3,opt,name=maxCount" json:"maxCount"`
	ReqAchievementContent bool     `protobuf:"varint,4,opt,name=reqAchievementContent" json:"reqAchievementContent"`
}

func (m *DE5BReqBody) Reset()         { *m = DE5BReqBody{} }
func (m *DE5BReqBody) String() string { return proto.CompactTextString(m) }
func (*DE5BReqBody) ProtoMessage()    {}
func (*DE5BReqBody) Descriptor() ([]byte, []int) {
	return fileDescriptor_306a22bb1626016b, []int{1}
}
func (m *DE5BReqBody) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *DE5BReqBody) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_DE5BReqBody.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *DE5BReqBody) XXX_Merge(src proto.Message) {
	xxx_messageInfo_DE5BReqBody.Merge(m, src)
}
func (m *DE5BReqBody) XXX_Size() int {
	return m.Size()
}
func (m *DE5BReqBody) XXX_DiscardUnknown() {
	xxx_messageInfo_DE5BReqBody.DiscardUnknown(m)
}

var xxx_messageInfo_DE5BReqBody proto.InternalMessageInfo

func (m *DE5BReqBody) GetUin() uint64 {
	if m != nil {
		return m.Uin
	}
	return 0
}

func (m *DE5BReqBody) GetAchievementId() []uint32 {
	if m != nil {
		return m.AchievementId
	}
	return nil
}

func (m *DE5BReqBody) GetMaxCount() uint32 {
	if m != nil {
		return m.MaxCount
	}
	return 0
}

func (m *DE5BReqBody) GetReqAchievementContent() bool {
	if m != nil {
		return m.ReqAchievementContent
	}
	return false
}

type DE5BRspBody struct {
	AchievementTotalCount uint32                 `protobuf:"varint,1,opt,name=achievementTotalCount" json:"achievementTotalCount"`
	LifeAchItem           []*LifeAchievementItem `protobuf:"bytes,2,rep,name=lifeAchItem" json:"lifeAchItem,omitempty"`
	AchievementOpenid     string                 `protobuf:"bytes,3,opt,name=achievementOpenid" json:"achievementOpenid"`
}

func (m *DE5BRspBody) Reset()         { *m = DE5BRspBody{} }
func (m *DE5BRspBody) String() string { return proto.CompactTextString(m) }
func (*DE5BRspBody) ProtoMessage()    {}
func (*DE5BRspBody) Descriptor() ([]byte, []int) {
	return fileDescriptor_306a22bb1626016b, []int{2}
}
func (m *DE5BRspBody) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *DE5BRspBody) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_DE5BRspBody.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *DE5BRspBody) XXX_Merge(src proto.Message) {
	xxx_messageInfo_DE5BRspBody.Merge(m, src)
}
func (m *DE5BRspBody) XXX_Size() int {
	return m.Size()
}
func (m *DE5BRspBody) XXX_DiscardUnknown() {
	xxx_messageInfo_DE5BRspBody.DiscardUnknown(m)
}

var xxx_messageInfo_DE5BRspBody proto.InternalMessageInfo

func (m *DE5BRspBody) GetAchievementTotalCount() uint32 {
	if m != nil {
		return m.AchievementTotalCount
	}
	return 0
}

func (m *DE5BRspBody) GetLifeAchItem() []*LifeAchievementItem {
	if m != nil {
		return m.LifeAchItem
	}
	return nil
}

func (m *DE5BRspBody) GetAchievementOpenid() string {
	if m != nil {
		return m.AchievementOpenid
	}
	return ""
}

func init() {
	proto.RegisterType((*LifeAchievementItem)(nil), "LifeAchievementItem")
	proto.RegisterType((*DE5BReqBody)(nil), "DE5BReqBody")
	proto.RegisterType((*DE5BRspBody)(nil), "DE5BRspBody")
}

func init() { proto.RegisterFile("client/pb/oidb/oidb0xe5b.proto", fileDescriptor_306a22bb1626016b) }

var fileDescriptor_306a22bb1626016b = []byte{
	// 370 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x6c, 0x52, 0xc1, 0x4e, 0xea, 0x40,
	0x14, 0xed, 0x00, 0x8f, 0xc0, 0xe5, 0x91, 0xf7, 0xde, 0x3c, 0x31, 0x5d, 0x8d, 0x93, 0x86, 0x45,
	0xe3, 0xa2, 0x10, 0x22, 0x2e, 0x70, 0x45, 0xd1, 0x85, 0x89, 0x51, 0x43, 0x5c, 0xb9, 0x2b, 0x74,
	0x0c, 0x93, 0xb4, 0x33, 0x05, 0x06, 0x83, 0x7f, 0xe1, 0x3f, 0xb8, 0xf2, 0x03, 0xfc, 0x07, 0x96,
	0x2c, 0x5d, 0x19, 0x03, 0x3f, 0x62, 0x28, 0x45, 0x07, 0xe8, 0xa6, 0x69, 0xce, 0x39, 0x73, 0xe7,
	0xdc, 0x33, 0x07, 0x48, 0x3f, 0xe0, 0x4c, 0xa8, 0x5a, 0xd4, 0xab, 0x49, 0xee, 0xaf, 0x3f, 0xf5,
	0x29, 0x6b, 0xf6, 0x9c, 0x68, 0x24, 0x95, 0xb4, 0x5e, 0x32, 0xf0, 0xff, 0x8a, 0x3f, 0xb0, 0x76,
	0x7f, 0xc0, 0xd9, 0x23, 0x0b, 0x99, 0x50, 0x97, 0x8a, 0x85, 0xf8, 0x18, 0xca, 0x9e, 0x06, 0xf9,
	0x26, 0xa2, 0xc8, 0x2e, 0xbb, 0xb9, 0xd9, 0xc7, 0x91, 0xd1, 0xdd, 0xa6, 0x70, 0x1d, 0xfe, 0x6a,
	0xc0, 0x1d, 0x57, 0x01, 0x33, 0x33, 0x14, 0xd9, 0xc5, 0x44, 0xbe, 0xc7, 0x62, 0x07, 0xfe, 0xe8,
	0x23, 0xfa, 0x52, 0x98, 0x59, 0xed, 0xc0, 0x2e, 0x89, 0xab, 0x00, 0x03, 0x6f, 0x7c, 0x3b, 0xf2,
	0xf8, 0x98, 0xf9, 0x66, 0x8e, 0x22, 0xbb, 0x90, 0x48, 0x35, 0x1c, 0x5b, 0x50, 0x8c, 0xe2, 0xdf,
	0xeb, 0x49, 0x68, 0xfe, 0xd2, 0xfc, 0xfe, 0xc0, 0xf8, 0x04, 0xb0, 0x36, 0xbc, 0x23, 0x85, 0x62,
	0x42, 0x99, 0x79, 0x8a, 0xec, 0xdf, 0x89, 0x38, 0x85, 0xb7, 0x5e, 0x11, 0x94, 0xce, 0x2f, 0x9a,
	0x6e, 0x97, 0x0d, 0x5d, 0xe9, 0x3f, 0xe1, 0x43, 0xc8, 0x4e, 0xb8, 0x88, 0x33, 0xc9, 0x25, 0xc7,
	0x56, 0x00, 0xae, 0xee, 0xa6, 0x96, 0xa1, 0x59, 0xbb, 0xbc, 0x9b, 0x17, 0x85, 0x42, 0xe8, 0x4d,
	0x3b, 0x72, 0x22, 0x54, 0xbc, 0xf6, 0xc6, 0xe6, 0x37, 0x8a, 0x5b, 0x50, 0x19, 0xb1, 0x61, 0x7b,
	0xdf, 0xa8, 0xbe, 0x7a, 0xba, 0xc4, 0x7a, 0xdb, 0x78, 0x1d, 0x47, 0xb1, 0xd7, 0x16, 0x54, 0xf4,
	0xfc, 0xa5, 0xf2, 0x82, 0xf5, 0xd5, 0xfa, 0x8b, 0xa6, 0x4b, 0xf0, 0x29, 0x94, 0x82, 0x75, 0x39,
	0x56, 0xa5, 0x88, 0xb7, 0x29, 0x35, 0x0e, 0x9c, 0x94, 0xc2, 0x74, 0x75, 0x21, 0x6e, 0xc0, 0x3f,
	0x6d, 0xe0, 0x4d, 0xc4, 0x04, 0xf7, 0xb7, 0x5e, 0x78, 0x9f, 0x76, 0xe9, 0x6c, 0x41, 0xd0, 0x7c,
	0x41, 0xd0, 0xe7, 0x82, 0xa0, 0xe7, 0x25, 0x31, 0xe6, 0x4b, 0x62, 0xbc, 0x2f, 0x89, 0x71, 0x9f,
	0x77, 0xce, 0x56, 0xb5, 0xfd, 0x0a, 0x00, 0x00, 0xff, 0xff, 0x48, 0xbe, 0xd7, 0xa1, 0xcc, 0x02,
	0x00, 0x00,
}

func (m *LifeAchievementItem) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *LifeAchievementItem) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *LifeAchievementItem) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.AchievementContent != nil {
		i -= len(m.AchievementContent)
		copy(dAtA[i:], m.AchievementContent)
		i = encodeVarintOidb0Xe5B(dAtA, i, uint64(len(m.AchievementContent)))
		i--
		dAtA[i] = 0x32
	}
	i = encodeVarintOidb0Xe5B(dAtA, i, uint64(m.PraiseNum))
	i--
	dAtA[i] = 0x28
	i--
	if m.HasPraised {
		dAtA[i] = 1
	} else {
		dAtA[i] = 0
	}
	i--
	dAtA[i] = 0x20
	i -= len(m.AchievementIcon)
	copy(dAtA[i:], m.AchievementIcon)
	i = encodeVarintOidb0Xe5B(dAtA, i, uint64(len(m.AchievementIcon)))
	i--
	dAtA[i] = 0x1a
	i -= len(m.AchievementTitle)
	copy(dAtA[i:], m.AchievementTitle)
	i = encodeVarintOidb0Xe5B(dAtA, i, uint64(len(m.AchievementTitle)))
	i--
	dAtA[i] = 0x12
	i = encodeVarintOidb0Xe5B(dAtA, i, uint64(m.AchievementId))
	i--
	dAtA[i] = 0x8
	return len(dAtA) - i, nil
}

func (m *DE5BReqBody) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *DE5BReqBody) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *DE5BReqBody) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	i--
	if m.ReqAchievementContent {
		dAtA[i] = 1
	} else {
		dAtA[i] = 0
	}
	i--
	dAtA[i] = 0x20
	i = encodeVarintOidb0Xe5B(dAtA, i, uint64(m.MaxCount))
	i--
	dAtA[i] = 0x18
	if len(m.AchievementId) > 0 {
		for iNdEx := len(m.AchievementId) - 1; iNdEx >= 0; iNdEx-- {
			i = encodeVarintOidb0Xe5B(dAtA, i, uint64(m.AchievementId[iNdEx]))
			i--
			dAtA[i] = 0x10
		}
	}
	i = encodeVarintOidb0Xe5B(dAtA, i, uint64(m.Uin))
	i--
	dAtA[i] = 0x8
	return len(dAtA) - i, nil
}

func (m *DE5BRspBody) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *DE5BRspBody) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *DE5BRspBody) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	i -= len(m.AchievementOpenid)
	copy(dAtA[i:], m.AchievementOpenid)
	i = encodeVarintOidb0Xe5B(dAtA, i, uint64(len(m.AchievementOpenid)))
	i--
	dAtA[i] = 0x1a
	if len(m.LifeAchItem) > 0 {
		for iNdEx := len(m.LifeAchItem) - 1; iNdEx >= 0; iNdEx-- {
			{
				size, err := m.LifeAchItem[iNdEx].MarshalToSizedBuffer(dAtA[:i])
				if err != nil {
					return 0, err
				}
				i -= size
				i = encodeVarintOidb0Xe5B(dAtA, i, uint64(size))
			}
			i--
			dAtA[i] = 0x12
		}
	}
	i = encodeVarintOidb0Xe5B(dAtA, i, uint64(m.AchievementTotalCount))
	i--
	dAtA[i] = 0x8
	return len(dAtA) - i, nil
}

func encodeVarintOidb0Xe5B(dAtA []byte, offset int, v uint64) int {
	offset -= sovOidb0Xe5B(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}
func (m *LifeAchievementItem) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	n += 1 + sovOidb0Xe5B(uint64(m.AchievementId))
	l = len(m.AchievementTitle)
	n += 1 + l + sovOidb0Xe5B(uint64(l))
	l = len(m.AchievementIcon)
	n += 1 + l + sovOidb0Xe5B(uint64(l))
	n += 2
	n += 1 + sovOidb0Xe5B(uint64(m.PraiseNum))
	if m.AchievementContent != nil {
		l = len(m.AchievementContent)
		n += 1 + l + sovOidb0Xe5B(uint64(l))
	}
	return n
}

func (m *DE5BReqBody) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	n += 1 + sovOidb0Xe5B(uint64(m.Uin))
	if len(m.AchievementId) > 0 {
		for _, e := range m.AchievementId {
			n += 1 + sovOidb0Xe5B(uint64(e))
		}
	}
	n += 1 + sovOidb0Xe5B(uint64(m.MaxCount))
	n += 2
	return n
}

func (m *DE5BRspBody) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	n += 1 + sovOidb0Xe5B(uint64(m.AchievementTotalCount))
	if len(m.LifeAchItem) > 0 {
		for _, e := range m.LifeAchItem {
			l = e.Size()
			n += 1 + l + sovOidb0Xe5B(uint64(l))
		}
	}
	l = len(m.AchievementOpenid)
	n += 1 + l + sovOidb0Xe5B(uint64(l))
	return n
}

func sovOidb0Xe5B(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozOidb0Xe5B(x uint64) (n int) {
	return sovOidb0Xe5B(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *LifeAchievementItem) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowOidb0Xe5B
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: LifeAchievementItem: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: LifeAchievementItem: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field AchievementId", wireType)
			}
			m.AchievementId = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowOidb0Xe5B
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.AchievementId |= uint32(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field AchievementTitle", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowOidb0Xe5B
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthOidb0Xe5B
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthOidb0Xe5B
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.AchievementTitle = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field AchievementIcon", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowOidb0Xe5B
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthOidb0Xe5B
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthOidb0Xe5B
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.AchievementIcon = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 4:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field HasPraised", wireType)
			}
			var v int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowOidb0Xe5B
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				v |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			m.HasPraised = bool(v != 0)
		case 5:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field PraiseNum", wireType)
			}
			m.PraiseNum = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowOidb0Xe5B
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.PraiseNum |= uint32(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 6:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field AchievementContent", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowOidb0Xe5B
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthOidb0Xe5B
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthOidb0Xe5B
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.AchievementContent = append(m.AchievementContent[:0], dAtA[iNdEx:postIndex]...)
			if m.AchievementContent == nil {
				m.AchievementContent = []byte{}
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipOidb0Xe5B(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthOidb0Xe5B
			}
			if (iNdEx + skippy) < 0 {
				return ErrInvalidLengthOidb0Xe5B
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *DE5BReqBody) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowOidb0Xe5B
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: DE5BReqBody: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: DE5BReqBody: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Uin", wireType)
			}
			m.Uin = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowOidb0Xe5B
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.Uin |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 2:
			if wireType == 0 {
				var v uint32
				for shift := uint(0); ; shift += 7 {
					if shift >= 64 {
						return ErrIntOverflowOidb0Xe5B
					}
					if iNdEx >= l {
						return io.ErrUnexpectedEOF
					}
					b := dAtA[iNdEx]
					iNdEx++
					v |= uint32(b&0x7F) << shift
					if b < 0x80 {
						break
					}
				}
				m.AchievementId = append(m.AchievementId, v)
			} else if wireType == 2 {
				var packedLen int
				for shift := uint(0); ; shift += 7 {
					if shift >= 64 {
						return ErrIntOverflowOidb0Xe5B
					}
					if iNdEx >= l {
						return io.ErrUnexpectedEOF
					}
					b := dAtA[iNdEx]
					iNdEx++
					packedLen |= int(b&0x7F) << shift
					if b < 0x80 {
						break
					}
				}
				if packedLen < 0 {
					return ErrInvalidLengthOidb0Xe5B
				}
				postIndex := iNdEx + packedLen
				if postIndex < 0 {
					return ErrInvalidLengthOidb0Xe5B
				}
				if postIndex > l {
					return io.ErrUnexpectedEOF
				}
				var elementCount int
				var count int
				for _, integer := range dAtA[iNdEx:postIndex] {
					if integer < 128 {
						count++
					}
				}
				elementCount = count
				if elementCount != 0 && len(m.AchievementId) == 0 {
					m.AchievementId = make([]uint32, 0, elementCount)
				}
				for iNdEx < postIndex {
					var v uint32
					for shift := uint(0); ; shift += 7 {
						if shift >= 64 {
							return ErrIntOverflowOidb0Xe5B
						}
						if iNdEx >= l {
							return io.ErrUnexpectedEOF
						}
						b := dAtA[iNdEx]
						iNdEx++
						v |= uint32(b&0x7F) << shift
						if b < 0x80 {
							break
						}
					}
					m.AchievementId = append(m.AchievementId, v)
				}
			} else {
				return fmt.Errorf("proto: wrong wireType = %d for field AchievementId", wireType)
			}
		case 3:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field MaxCount", wireType)
			}
			m.MaxCount = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowOidb0Xe5B
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.MaxCount |= uint32(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 4:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field ReqAchievementContent", wireType)
			}
			var v int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowOidb0Xe5B
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				v |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			m.ReqAchievementContent = bool(v != 0)
		default:
			iNdEx = preIndex
			skippy, err := skipOidb0Xe5B(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthOidb0Xe5B
			}
			if (iNdEx + skippy) < 0 {
				return ErrInvalidLengthOidb0Xe5B
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *DE5BRspBody) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowOidb0Xe5B
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: DE5BRspBody: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: DE5BRspBody: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field AchievementTotalCount", wireType)
			}
			m.AchievementTotalCount = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowOidb0Xe5B
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.AchievementTotalCount |= uint32(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field LifeAchItem", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowOidb0Xe5B
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthOidb0Xe5B
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthOidb0Xe5B
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.LifeAchItem = append(m.LifeAchItem, &LifeAchievementItem{})
			if err := m.LifeAchItem[len(m.LifeAchItem)-1].Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field AchievementOpenid", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowOidb0Xe5B
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthOidb0Xe5B
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthOidb0Xe5B
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.AchievementOpenid = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipOidb0Xe5B(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthOidb0Xe5B
			}
			if (iNdEx + skippy) < 0 {
				return ErrInvalidLengthOidb0Xe5B
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func skipOidb0Xe5B(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	depth := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowOidb0Xe5B
			}
			if iNdEx >= l {
				return 0, io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		wireType := int(wire & 0x7)
		switch wireType {
		case 0:
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowOidb0Xe5B
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				iNdEx++
				if dAtA[iNdEx-1] < 0x80 {
					break
				}
			}
		case 1:
			iNdEx += 8
		case 2:
			var length int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowOidb0Xe5B
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				length |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if length < 0 {
				return 0, ErrInvalidLengthOidb0Xe5B
			}
			iNdEx += length
		case 3:
			depth++
		case 4:
			if depth == 0 {
				return 0, ErrUnexpectedEndOfGroupOidb0Xe5B
			}
			depth--
		case 5:
			iNdEx += 4
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
		if iNdEx < 0 {
			return 0, ErrInvalidLengthOidb0Xe5B
		}
		if depth == 0 {
			return iNdEx, nil
		}
	}
	return 0, io.ErrUnexpectedEOF
}

var (
	ErrInvalidLengthOidb0Xe5B        = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowOidb0Xe5B          = fmt.Errorf("proto: integer overflow")
	ErrUnexpectedEndOfGroupOidb0Xe5B = fmt.Errorf("proto: unexpected end of group")
)
