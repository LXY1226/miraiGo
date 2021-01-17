package message

import (
	"encoding/hex"
	"github.com/Mrs4s/MiraiGo/binary"
	"github.com/Mrs4s/MiraiGo/client/pb/msg"
	"github.com/gogo/protobuf/proto"
)

var imgOld = []byte{0x15, 0x36, 0x20, 0x39, 0x32, 0x6B, 0x41, 0x31, 0x00, 0x38, 0x37, 0x32, 0x66, 0x30, 0x36, 0x36, 0x30, 0x33, 0x61, 0x65, 0x31, 0x30, 0x33, 0x62, 0x37, 0x20, 0x20, 0x20, 0x20, 0x20,
	0x20, 0x35, 0x30, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x7B, 0x30, 0x31, 0x45, 0x39, 0x34, 0x35, 0x31, 0x42, 0x2D, 0x37, 0x30, 0x45, 0x44,
	0x2D, 0x45, 0x41, 0x45, 0x33, 0x2D, 0x42, 0x33, 0x37, 0x43, 0x2D, 0x31, 0x30, 0x31, 0x46, 0x31, 0x45, 0x45, 0x42, 0x46, 0x35, 0x42, 0x35, 0x7D, 0x2E, 0x70, 0x6E, 0x67, 0x41}

func (e *TextElement) Pack() (r []*msg.Elem) {
	r = append(r, &msg.Elem{
		Text: &msg.Text{
			Str: e.Content,
		},
	})
	return
}

func (e *FaceElement) Pack() (r []*msg.Elem) {
	r = []*msg.Elem{}
	if e.NewSysFace {
		elem := &msg.MsgElemInfoServtype33{
			Index:  uint32(e.Index),
			Text:   []byte("/" + e.Name),
			Compat: []byte("/" + e.Name),
		}
		b, _ := proto.Marshal(elem)
		r = append(r, &msg.Elem{
			CommonElem: &msg.CommonElem{
				ServiceType:  33,
				PbElem:       b,
				BusinessType: 1,
			},
		})
	} else {
		r = append(r, &msg.Elem{
			Face: &msg.Face{
				Index: e.Index,
				Old:   binary.ToBytes(int16(0x1445 - 4 + e.Index)),
				Buf:   []byte{0x00, 0x01, 0x00, 0x04, 0x52, 0xCC, 0xF5, 0xD0},
			},
		})
	}
	return
}

func (e *AtElement) Pack() (r []*msg.Elem) {
	r = []*msg.Elem{}
	r = append(r, &msg.Elem{
		Text: &msg.Text{
			Str: e.Display,
			Attr6Buf: binary.NewWriterF(func(w *binary.Writer) {
				w.WriteUInt16(1)
				w.WriteUInt16(0)
				w.WriteUInt16(uint16(len([]rune(e.Display))))
				w.WriteByte(func() byte {
					if e.Target == 0 {
						return 1
					}
					return 0
				}())
				w.WriteUInt32(uint32(e.Target))
				w.WriteUInt16(0)
			}),
		},
	})
	r = append(r, &msg.Elem{Text: &msg.Text{Str: " "}})
	return
}

func (e *ImageElement) Pack() (r []*msg.Elem) {
	r = []*msg.Elem{}
	r = append(r, &msg.Elem{
		CustomFace: &msg.CustomFace{
			FilePath: e.Filename,
			Md5:      e.Md5,
			Size_:    e.Size,
			Flag:     make([]byte, 4),
			OldData:  imgOld,
		},
	})
	return
}

func (e *GroupImageElement) Pack() (r []*msg.Elem) {
	r = []*msg.Elem{}
	r = append(r, &msg.Elem{
		CustomFace: &msg.CustomFace{
			FileType: 66,
			Useful:   1,
			//Origin:    1,
			BizType:   5,
			Width:     e.Width,
			Height:    e.Height,
			FileId:    int32(e.FileId),
			FilePath:  e.ImageId,
			ImageType: e.ImageType,
			Size_:     e.Size,
			Md5:       e.Md5[:],
			Flag:      make([]byte, 4),
			//OldData:  imgOld,
		},
	})
	return
}

func (e *FriendImageElement) Pack() (r []*msg.Elem) {
	r = []*msg.Elem{}
	r = append(r, &msg.Elem{
		NotOnlineImage: &msg.NotOnlineImage{
			FilePath:     e.ImageId,
			ResId:        e.ImageId,
			OldPicMd5:    false,
			PicMd5:       e.Md5,
			DownloadPath: e.ImageId,
			Original:     1,
			PbReserve:    []byte{0x78, 0x02},
		},
	})
	return
}

func (e *ServiceElement) Pack() (r []*msg.Elem) {
	r = []*msg.Elem{}
	// id =35 已移至 ForwardElement
	if e.Id == 33 {
		r = append(r, &msg.Elem{
			Text: &msg.Text{Str: e.ResId},
		})
		r = append(r, &msg.Elem{
			RichMsg: &msg.RichMsg{
				Template1: append([]byte{1}, binary.ZlibCompress([]byte(e.Content))...),
				ServiceId: e.Id,
				MsgResId:  []byte{},
			},
		})
		return
	}
	r = append(r, &msg.Elem{
		RichMsg: &msg.RichMsg{
			Template1: append([]byte{1}, binary.ZlibCompress([]byte(e.Content))...),
			ServiceId: e.Id,
		},
	})
	return
}

func (e *ForwardElement) Pack() (r []*msg.Elem) {
	r = []*msg.Elem{}
	r = append(r, &msg.Elem{
		RichMsg: &msg.RichMsg{
			Template1: append([]byte{1}, binary.ZlibCompress([]byte(e.Content))...),
			ServiceId: 35,
			MsgResId:  []byte{},
		},
	})
	r = append(r, &msg.Elem{
		Text: &msg.Text{
			Str: "你的QQ暂不支持查看[转发多条消息]，请期待后续版本。",
		},
	})
	return
}

func (e *LightAppElement) Pack() (r []*msg.Elem) {
	r = []*msg.Elem{}
	r = append(r, &msg.Elem{
		LightApp: &msg.LightAppElem{
			Data: append([]byte{1}, binary.ZlibCompress([]byte(e.Content))...),
			// MsgResid: []byte{1},
		},
	})
	return
}

func (e *FriendFlashPicElement) Pack() (r []*msg.Elem) {
	r = []*msg.Elem{}
	flash := &msg.MsgElemInfoServtype3{
		FlashC2CPic: &msg.NotOnlineImage{
			FilePath:     e.ImageId,
			ResId:        e.ImageId,
			OldPicMd5:    false,
			PicMd5:       e.Md5,
			DownloadPath: e.ImageId,
			Original:     1,
			PbReserve:    []byte{0x78, 0x02},
		},
	}
	data, _ := proto.Marshal(flash)
	r = append(r, &msg.Elem{
		CommonElem: &msg.CommonElem{
			ServiceType: 3,
			PbElem:      data,
		},
	})
	r = append(r, &msg.Elem{
		Text: &msg.Text{
			Str: "[闪照]请使用新版手机QQ查看闪照。",
		},
	})
	return
}

func (e *GroupFlashPicElement) Pack() (r []*msg.Elem) {
	r = []*msg.Elem{}
	flash := &msg.MsgElemInfoServtype3{
		FlashTroopPic: &msg.CustomFace{
			FileType: 66,
			Useful:   1,
			Origin:   1,
			FileId:   int32(e.FileId),
			FilePath: e.ImageId,
			Size_:    e.Size,
			Md5:      e.Md5[:],
			Flag:     make([]byte, 4),
		},
	}
	data, _ := proto.Marshal(flash)
	r = append(r, &msg.Elem{
		CommonElem: &msg.CommonElem{
			ServiceType: 3,
			PbElem:      data,
		},
	})
	r = append(r, &msg.Elem{
		Text: &msg.Text{
			Str: "[闪照]请使用新版手机QQ查看闪照。",
		},
	})
	return
}

func (e *GroupShowPicElement) Pack() (r []*msg.Elem) {
	r = []*msg.Elem{}
	res := &msg.ResvAttr{ImageShow: &msg.AnimationImageShow{
		EffectId:       e.EffectId,
		AnimationParam: []byte("{}"),
	}}
	reserve, _ := proto.Marshal(res)
	r = append(r, &msg.Elem{
		CustomFace: &msg.CustomFace{
			FileType:  0,
			Useful:    1,
			ImageType: 1001,
			FileId:    int32(e.FileId),
			FilePath:  e.ImageId,
			Size_:     e.Size,
			Md5:       e.Md5[:],
			Flag:      []byte{0x11, 0x00, 0x00, 0x00},
			//OldData:  imgOld,
			PbReserve: reserve,
		},
	})
	return
}

func (e *ShortVideoElement) Pack() (r []*msg.Elem) {
	r = append(r, &msg.Elem{
		Text: &msg.Text{
			Str: "你的QQ暂不支持查看视频短片，请期待后续版本。",
		},
	})
	r = append(r, &msg.Elem{
		VideoFile: &msg.VideoFile{
			FileUuid:               e.Uuid,
			FileMd5:                e.Md5,
			FileName:               []byte(hex.EncodeToString(e.Md5) + ".mp4"),
			FileFormat:             3,
			FileTime:               10,
			FileSize:               e.Size,
			ThumbWidth:             1280,
			ThumbHeight:            720,
			ThumbFileMd5:           e.ThumbMd5,
			ThumbFileSize:          e.ThumbSize,
			BusiType:               0,
			FromChatType:           -1,
			ToChatType:             -1,
			BoolSupportProgressive: true,
			FileWidth:              1280,
			FileHeight:             720,
		},
	})
	return
}
