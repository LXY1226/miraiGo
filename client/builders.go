package client

import (
	"crypto/md5"
	binary2 "encoding/binary"
	"encoding/hex"
	"github.com/Mrs4s/MiraiGo/binary"
	"github.com/Mrs4s/MiraiGo/binary/jce"
	"github.com/Mrs4s/MiraiGo/client/pb"
	"github.com/Mrs4s/MiraiGo/client/pb/cmd0x352"
	"github.com/Mrs4s/MiraiGo/client/pb/msg"
	"github.com/Mrs4s/MiraiGo/client/pb/multimsg"
	"github.com/Mrs4s/MiraiGo/client/pb/oidb"
	"github.com/Mrs4s/MiraiGo/client/pb/pttcenter"
	"github.com/Mrs4s/MiraiGo/client/pb/structmsg"
	"github.com/Mrs4s/MiraiGo/message"
	"github.com/Mrs4s/MiraiGo/protocol/crypto"
	"github.com/Mrs4s/MiraiGo/protocol/packets"
	"github.com/Mrs4s/MiraiGo/protocol/tlv"
	"github.com/Mrs4s/MiraiGo/utils"
	"github.com/golang/protobuf/proto"
	"math/rand"
	"strconv"
	"time"
)

var (
	syncConst1 = rand.Int63()
	syncConst2 = rand.Int63()
)

func (c *QQClient) buildLoginPacket() (uint16, []byte) {
	seq := c.nextSeq()
	req := packets.BuildOicqRequestPacket(c.Uin, 0x0810, crypto.ECDH, c.RandomKey, func(w *binary.Writer) {
		w.Write([]byte{
			0x00, 0x09, //[0] Subcommand9
			0x00, 0x11, //[2] count of TLVs, probably ignored by server?
			0x01, 0x16, //[4] Tag0x116 静态数据
			0x00, 0x0e, //[6] Length
			0x00,                   //[8] _ver
			0x0a, 0xf7, 0xff, 0x7c, //[9] miscBitmap
			0x00, 0x01, 0x04, 0x00, //[13] subSigMap
			0x01,                   //[17] sizeOf(appIdList)
			0x5f, 0x5e, 0x10, 0xe2, //[18] appIdList

			0x00, 0x08, //[22] Tag0x8 静态数据
			0x00, 0x08, //[24] Length
			0x00, 0x00, //[26]
			0x00, 0x00, 0x08, 0x04, //[28] localId
			0x00, 0x00, //[32]

			0x01, 0x00, //[34] Tag0x100 静态数据
			0x00, 0x16, //[36] Length
			0x00, 0x01, //[38] db_buf_ver
			0x00, 0x00, 0x00, 0x05, //[40] sso_ver
			0x00, 0x00, 0x00, 0x10, //[44] appId
			0x20, 0x02, 0xec, 0x09, //[48] subAppId
			0x00, 0x00, 0x00, 0x00, //[52] appClientVersion
			0x02, 0x14, 0x10, 0xe0, //[56] sigMap

			0x01, 0x07, //[60] Tag0x107 静态数据
			0x00, 0x06, //[62] Length
			0x00, 0x00, //[64] picType
			0x00,       //[66] const1_always_0
			0x00, 0x00, //[67] const2_always_0
			0x01, //[69] const3_always_1

			0x01, 0x42, //[70] Tag0x142 静态数据
			0x00, 0x18, //[72] Length
			0x00, 0x00, //[74] _version
			0x00, 0x14, //[76] Length
			0x63, 0x6f, 0x6d, 0x2e, 0x74, 0x65, 0x6e, 0x63, 0x65, 0x6e, 0x74, 0x2e, 0x6d, 0x6f, 0x62, 0x69, 0x6c, 0x65, 0x71, 0x71, //[78] com.tencent.mobileqq

			0x01, 0x47, //[98] Tag0x147 静态数据
			0x00, 0x1d, //[100] Length
			0x00, 0x00, 0x00, 0x10, //[102] appId
			0x00, 0x05, //[106] Length
			0x38, 0x2e, 0x32, 0x2e, 0x37, //[108] apkVersionName
			0x00, 0x10, //[113] Length
			0xa6, 0xb7, 0x45, 0xbf, 0x24, 0xa2, 0xc2, 0x77, 0x52, 0x77, 0x16, 0xf6, 0xf3, 0x6e, 0xb6, 0x8d, //[115] apkSignatureMd5

			0x01, 0x77, //[131] Tag0x177 静态数据
			0x00, 0x11, //[133] Length
			0x01,                   //[135]
			0x5d, 0xa6, 0x84, 0x42, //[136]
			0x00, 0x0a, //[140] Length
			0x36, 0x2e, 0x30, 0x2e, 0x30, 0x2e, 0x32, 0x34, 0x31, 0x33, //[142] 6.0.0.2413

			0x05, 0x16, //[152] Tag0x516 静态数据
			0x00, 0x04, //[154] Length
			0x00, 0x00, 0x00, 0x00, //[156]

			0x05, 0x21, //[160] Tag0x521 静态数据
			0x00, 0x06, //[162] Length
			0x00, 0x00, 0x00, 0x00, //[164]
			0x00, 0x00, //[168]

			0x05, 0x25, //[170] Tag0x525 静态数据
			0x00, 0x08, //[172] Length
			0x00, 0x01, //[174]
			0x05, 0x36, //[176] Tag0x536
			0x00, 0x02, //[178] Length
			0x01, //[180] const
			0x00, //[181] data count

			0x05, 0x11, //[182] Tag0x511 静态数据
			0x00, 0xcb, //[184] Length
			0x00, 0x0e, //[186] Length
			0x01,       //[188]
			0x00, 0x0a, //[189] Length
			0x74, 0x65, 0x6e, 0x70, 0x61, 0x79, 0x2e, 0x63, 0x6f, 0x6d, //[191] tenpay.com
			0x01,       //[201]
			0x00, 0x11, //[202] Length
			0x6f, 0x70, 0x65, 0x6e, 0x6d, 0x6f, 0x62, 0x69, 0x6c, 0x65, 0x2e, 0x71, 0x71, 0x2e, 0x63, 0x6f, 0x6d, //[204] openmobile.qq.com
			0x01,       //[221]
			0x00, 0x0b, //[222] Length
			0x64, 0x6f, 0x63, 0x73, 0x2e, 0x71, 0x71, 0x2e, 0x63, 0x6f, 0x6d, //[224] docs.qq.com
			0x01,       //[235]
			0x00, 0x0e, //[236] Length
			0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x2e, 0x71, 0x71, 0x2e, 0x63, 0x6f, 0x6d, //[238] connect.qq.com
			0x01,       //[252]
			0x00, 0x0c, //[253] Length
			0x71, 0x7a, 0x6f, 0x6e, 0x65, 0x2e, 0x71, 0x71, 0x2e, 0x63, 0x6f, 0x6d, //[255] qzone.qq.com
			0x01,       //[267]
			0x00, 0x0a, //[268] Length
			0x76, 0x69, 0x70, 0x2e, 0x71, 0x71, 0x2e, 0x63, 0x6f, 0x6d, //[270] vip.qq.com
			0x01,       //[280]
			0x00, 0x0a, //[281] Length
			0x71, 0x75, 0x6e, 0x2e, 0x71, 0x71, 0x2e, 0x63, 0x6f, 0x6d, //[283] qun.qq.com
			0x01,       //[293]
			0x00, 0x0b, //[294] Length
			0x67, 0x61, 0x6d, 0x65, 0x2e, 0x71, 0x71, 0x2e, 0x63, 0x6f, 0x6d, //[296] game.qq.com
			0x01,       //[307]
			0x00, 0x0c, //[308] Length
			0x71, 0x71, 0x77, 0x65, 0x62, 0x2e, 0x71, 0x71, 0x2e, 0x63, 0x6f, 0x6d, //[310] qqweb.qq.com
			0x01,       //[322]
			0x00, 0x0d, //[323] Length
			0x6f, 0x66, 0x66, 0x69, 0x63, 0x65, 0x2e, 0x71, 0x71, 0x2e, 0x63, 0x6f, 0x6d, //[325] office.qq.com
			0x01,       //[338]
			0x00, 0x09, //[339] Length
			0x74, 0x69, 0x2e, 0x71, 0x71, 0x2e, 0x63, 0x6f, 0x6d, //[341] ti.qq.com
			0x01,       //[350]
			0x00, 0x0b, //[351] Length
			0x6d, 0x61, 0x69, 0x6c, 0x2e, 0x71, 0x71, 0x2e, 0x63, 0x6f, 0x6d, //[353] mail.qq.com
			0x01,       //[364]
			0x00, 0x09, //[365] Length
			0x71, 0x7a, 0x6f, 0x6e, 0x65, 0x2e, 0x63, 0x6f, 0x6d, //[367] qzone.com
			0x01,       //[376]
			0x00, 0x0a, //[377] Length
			0x6d, 0x6d, 0x61, 0x2e, 0x71, 0x71, 0x2e, 0x63, 0x6f, 0x6d, //[379] mma.qq.com

			0x01, 0x91, //[389] Tag0x191 静态数据
			0x00, 0x01, //[391] Length
			0x82, //[393]

			0x00, 0x18, //[394] Tag0x18 动态 uin
			0x00, 0x16, //[396] Length
			0x00, 0x01, //[398] _ping_version
			0x00, 0x00, 0x06, 0x00, //[400] _sso_version
			0x00, 0x00, 0x00, 0x10, //[404] appId
			0x00, 0x00, 0x00, 0x00, //[408] appClientVersion
			0x00, 0x00, 0x00, 0x00, //[412] !!uin
			0x00, 0x00, //[416] constant1_always_0
			0x00, 0x00, //[418]

			0x00, 0x01, //[420] Tag0x1 动态 randomInt uin currentTimeMillis ipaddr
			0x00, 0x14, //[422] Length
			0x00, 0x01, //[424] _ip_ver
			0x00, 0x00, 0x00, 0x00, //[426] !randomInt
			0x00, 0x00, 0x00, 0x00, //[430] !!uin
			0x00, 0x00, 0x00, 0x00, //[434] !!currentTimeMillis
			0x00, 0x00, 0x00, 0x00, //[438] !!ipaddr
			0x00, 0x00, //[442]

			//0x01, 0x54, //[444] Tag0x154 动态 ssoSequenceId
			//0x00, 0x04, //[446] Length
			//0x00, 0x00, 0x00, 0x10, //[448] !!!ssoSequenceId
			//
			//0x01, 0x45, //[452] Tag0x145 动态 MD5
			//0x00, 0x10, //[454] Length
			//0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //[456] !!MD5((androidId + macAddress)//generateGuid )
			//
			//0x01, 0x87, //[472] Tag0x187 动态 MD5
			//0x00, 0x10, //[474] Length
			//0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //[476] !!MD5(client.device.macAddress// may be md5)
			//
			//0x01, 0x88, //[492] Tag0x188 动态 MD5
			//0x00, 0x10, //[494] Length
			//0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //[496] !!MD5(client.device.androidId)
			//
			//0x01, 0x94, //[512] Tag0x194 动态 MD5
			//0x00, 0x10, //[514] Length
			//0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //[516] !!MD5(client.device.imsiMd5)
			//
			//0x02, 0x02, //[628] Tag0x202 静态
			//0x00, 0x1c, //[630] Length
			//0x00, 0x11, //[632] Length
			//0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, //[634] client.device.wifiBSSID
			//0x00, 0x07, //[651] Length
			//0x54, 0x50, 0x5f, 0x41, 0x53, 0x55, 0x53, //[653] client.device.wifiSSID
			//
			//0x01, 0x41, //[660] Tag0x141 静态
			//0x00, 0x14, //[662] Length
			//0x00, 0x01, //[664] version
			//0x00, 0x08, //[666] Length
			//0x54, 0x2d, 0x4d, 0x6f, 0x62, 0x69, 0x6c, 0x65, //[668] client.device.simInfo
			//0x00, 0x02, //[676] networkType WIFI
			//0x00, 0x04, //[678] Length
			//0x77, 0x69, 0x66, 0x69, //[680] client.device.apn
		})
		binary2.BigEndian.PutUint32((*w)[412:], uint32(c.Uin)) // t18

		binary2.BigEndian.PutUint32((*w)[426:], rand.Uint32())                     // t1
		binary2.BigEndian.PutUint32((*w)[430:], uint32(c.Uin))                     // t1
		binary2.BigEndian.PutUint32((*w)[434:], uint32(time.Now().UnixNano()/1e6)) // t1
		copy((*w)[438:], SystemDeviceInfo.IpAddress)                               // t1

		//binary2.BigEndian.PutUint32((*w)[448:], uint32(seq))   // t154

		//m := md5.Sum(SystemDeviceInfo.Guid)
		//copy((*w)[456:], m[:]) // t145
		//
		//m = md5.Sum(SystemDeviceInfo.MacAddress)
		//copy((*w)[476:], m[:]) // t187
		//
		//m = md5.Sum(SystemDeviceInfo.AndroidId)
		//copy((*w)[496:], m[:]) // t188
		//
		//copy((*w)[516:], SystemDeviceInfo.IMSIMd5) // t194

		w.Write(tlv.T106(uint32(c.Uin), 0, c.PasswordMd5, true, SystemDeviceInfo.Guid, SystemDeviceInfo.TgtgtKey))

		w.Write(tlv.T144(
			SystemDeviceInfo.AndroidId,
			SystemDeviceInfo.GenDeviceInfoData(),
			SystemDeviceInfo.OSType,
			SystemDeviceInfo.Version.Release,
			SystemDeviceInfo.SimInfo,
			SystemDeviceInfo.APN,
			false, true, false, tlv.GuidFlag(),
			SystemDeviceInfo.Model,
			SystemDeviceInfo.Guid,
			SystemDeviceInfo.Brand,
			SystemDeviceInfo.TgtgtKey,
		))

		w.Write(tlv.T145(SystemDeviceInfo.Guid))

		w.Write(tlv.T154(seq))
		w.Write(tlv.T141(SystemDeviceInfo.SimInfo, SystemDeviceInfo.APN))

		w.Write(tlv.T187(SystemDeviceInfo.MacAddress))
		w.Write(tlv.T188(SystemDeviceInfo.AndroidId))
		if len(SystemDeviceInfo.IMSIMd5) != 0 {
			w.Write(tlv.T194(SystemDeviceInfo.IMSIMd5))
		}
		if len(SystemDeviceInfo.WifiBSSID) != 0 && len(SystemDeviceInfo.WifiSSID) != 0 {
			w.Write(tlv.T202(SystemDeviceInfo.WifiBSSID, SystemDeviceInfo.WifiSSID))
		}
	})
	sso := packets.BuildSsoPacket(seq, "wtlogin.login", SystemDeviceInfo.IMEI, []byte{}, c.OutGoingPacketSessionId, req, c.ksid)
	packet := packets.BuildLoginPacket(c.Uin, 2, make([]byte, 16), sso, []byte{})
	return seq, packet
}

func (c *QQClient) buildDeviceLockLoginPacket(t402 []byte) (uint16, []byte) {
	seq := c.nextSeq()
	req := packets.BuildOicqRequestPacket(c.Uin, 0x0810, crypto.ECDH, c.RandomKey, func(w *binary.Writer) {
		w.WriteUInt16(20)
		w.WriteUInt16(4)

		w.Write(tlv.T8(2052))
		w.Write(tlv.T104(c.t104))
		w.Write(tlv.T116(150470524, 66560))
		h := md5.Sum(append(append(SystemDeviceInfo.Guid, []byte("stMNokHgxZUGhsYp")...), t402...))
		w.Write(tlv.T401(h[:]))
	})
	sso := packets.BuildSsoPacket(seq, "wtlogin.login", SystemDeviceInfo.IMEI, []byte{}, c.OutGoingPacketSessionId, req, c.ksid)
	packet := packets.BuildLoginPacket(c.Uin, 2, make([]byte, 16), sso, []byte{})
	return seq, packet
}

func (c *QQClient) buildCaptchaPacket(result string, sign []byte) (uint16, []byte) {
	seq := c.nextSeq()
	req := packets.BuildOicqRequestPacket(c.Uin, 0x0810, crypto.ECDH, c.RandomKey, func(w *binary.Writer) {
		w.WriteUInt16(2) // sub command
		w.WriteUInt16(4)
		w.Write(tlv.T2(result, sign))
		w.Write(tlv.T8(2052))
		w.Write(tlv.T104(c.t104))
		w.Write(tlv.T116(150470524, 66560))
	})
	sso := packets.BuildSsoPacket(seq, "wtlogin.login", SystemDeviceInfo.IMEI, []byte{}, c.OutGoingPacketSessionId, req, c.ksid)
	packet := packets.BuildLoginPacket(c.Uin, 2, make([]byte, 16), sso, []byte{})
	return seq, packet
}

// StatSvc.register
func (c *QQClient) buildClientRegisterPacket() (uint16, []byte) {
	seq := c.nextSeq()
	svc := &jce.SvcReqRegister{
		ConnType:     0,
		Uin:          c.Uin,
		Bid:          1 | 2 | 4,
		Status:       11,
		KickPC:       0,
		KickWeak:     0,
		IOSVersion:   int64(SystemDeviceInfo.Version.Sdk),
		NetType:      1,
		RegType:      0,
		Guid:         SystemDeviceInfo.Guid,
		IsSetStatus:  0,
		LocaleId:     2052,
		DevName:      string(SystemDeviceInfo.Model),
		DevType:      string(SystemDeviceInfo.Model),
		OSVer:        string(SystemDeviceInfo.Version.Release),
		OpenPush:     1,
		LargeSeq:     1551,
		OldSSOIp:     0,
		NewSSOIp:     31806887127679168,
		ChannelNo:    "",
		CPID:         0,
		VendorName:   "MIUI",
		VendorOSName: "ONEPLUS A5000_23_17",
		B769:         []byte{0x0A, 0x04, 0x08, 0x2E, 0x10, 0x00, 0x0A, 0x05, 0x08, 0x9B, 0x02, 0x10, 0x00},
		SetMute:      0,
	}
	b := append([]byte{0x0A}, svc.ToBytes()...)
	b = append(b, 0x0B)
	buf := &jce.RequestDataVersion3{
		Map: map[string][]byte{"SvcReqRegister": b},
	}
	pkt := &jce.RequestPacket{
		IVersion:     3,
		SServantName: "PushService",
		SFuncName:    "SvcReqRegister",
		SBuffer:      buf.ToBytes(),
		Context:      make(map[string]string),
		Status:       make(map[string]string),
	}
	sso := packets.BuildSsoPacket(seq, "StatSvc.register", SystemDeviceInfo.IMEI, c.sigInfo.tgt, c.OutGoingPacketSessionId, pkt.ToBytes(), c.ksid)
	packet := packets.BuildLoginPacket(c.Uin, 1, c.sigInfo.d2Key, sso, c.sigInfo.d2)
	return seq, packet
}

// ConfigPushSvc.PushResp
func (c *QQClient) buildConfPushRespPacket(t int32, pktSeq int64, jceBuf []byte) (uint16, []byte) {
	seq := c.nextSeq()
	req := jce.NewJceWriter()
	req.WriteInt32(t, 1)
	req.WriteInt64(pktSeq, 2)
	req.WriteBytes(jceBuf, 3)
	buf := &jce.RequestDataVersion3{
		Map: map[string][]byte{"PushResp": packRequestDataV3(req.Bytes())},
	}
	pkt := &jce.RequestPacket{
		IVersion:     3,
		SServantName: "QQService.ConfigPushSvc.MainServant",
		SFuncName:    "PushResp",
		SBuffer:      buf.ToBytes(),
		Context:      make(map[string]string),
		Status:       make(map[string]string),
	}
	packet := packets.BuildUniPacket(c.Uin, seq, "ConfigPushSvc.PushResp", 1, c.OutGoingPacketSessionId, []byte{}, c.sigInfo.d2Key, pkt.ToBytes())
	return seq, packet
}

// friendlist.getFriendGroupList
func (c *QQClient) buildFriendGroupListRequestPacket(friendStartIndex, friendListCount, groupStartIndex, groupListCount int16) (uint16, []byte) {
	seq := c.nextSeq()
	d50, _ := proto.Marshal(&pb.D50ReqBody{
		Appid:                   1002,
		ReqMusicSwitch:          1,
		ReqMutualmarkAlienation: 1,
		ReqKsingSwitch:          1,
		ReqMutualmarkLbsshare:   1,
	})
	req := &jce.FriendListRequest{
		Reqtype: 3,
		IfReflush: func() byte {
			if friendStartIndex <= 0 {
				return 0
			}
			return 1
		}(),
		Uin:         c.Uin,
		StartIndex:  friendStartIndex,
		FriendCount: friendListCount,
		GroupId:     0,
		IfGetGroupInfo: func() byte {
			if groupListCount <= 0 {
				return 0
			}
			return 1
		}(),
		GroupStartIndex: byte(groupStartIndex),
		GroupCount:      byte(groupListCount),
		IfGetMSFGroup:   0,
		IfShowTermType:  1,
		Version:         27,
		UinList:         nil,
		AppType:         0,
		IfGetDOVId:      0,
		IfGetBothFlag:   0,
		D50:             d50,
		D6B:             []byte{},
		SnsTypeList:     []int64{13580, 13581, 13582},
	}
	buf := &jce.RequestDataVersion3{
		Map: map[string][]byte{"FL": packRequestDataV3(req.ToBytes())},
	}
	pkt := &jce.RequestPacket{
		IVersion:     3,
		CPacketType:  0x003,
		IRequestId:   1921334514,
		SServantName: "mqq.IMService.FriendListServiceServantObj",
		SFuncName:    "GetFriendListReq",
		SBuffer:      buf.ToBytes(),
		Context:      make(map[string]string),
		Status:       make(map[string]string),
	}
	packet := packets.BuildUniPacket(c.Uin, seq, "friendlist.getFriendGroupList", 1, c.OutGoingPacketSessionId, []byte{}, c.sigInfo.d2Key, pkt.ToBytes())
	return seq, packet
}

// friendlist.GetTroopListReqV2
func (c *QQClient) buildGroupListRequestPacket() (uint16, []byte) {
	seq := c.nextSeq()
	req := &jce.TroopListRequest{
		Uin:              c.Uin,
		GetMSFMsgFlag:    1,
		Cookies:          []byte{},
		GroupInfo:        []int64{},
		GroupFlagExt:     1,
		Version:          7,
		CompanyId:        0,
		VersionNum:       1,
		GetLongGroupName: 1,
	}
	b := append([]byte{0x0A}, req.ToBytes()...)
	b = append(b, 0x0B)
	buf := &jce.RequestDataVersion3{
		Map: map[string][]byte{"GetTroopListReqV2Simplify": b},
	}
	pkt := &jce.RequestPacket{
		IVersion:     3,
		CPacketType:  0x00,
		IRequestId:   c.nextPacketSeq(),
		SServantName: "mqq.IMService.FriendListServiceServantObj",
		SFuncName:    "GetTroopListReqV2Simplify",
		SBuffer:      buf.ToBytes(),
		Context:      make(map[string]string),
		Status:       make(map[string]string),
	}
	packet := packets.BuildUniPacket(c.Uin, seq, "friendlist.GetTroopListReqV2", 1, c.OutGoingPacketSessionId, []byte{}, c.sigInfo.d2Key, pkt.ToBytes())
	return seq, packet
}

// friendlist.GetTroopMemberListReq
func (c *QQClient) buildGroupMemberListRequestPacket(groupUin, groupCode, nextUin int64) (uint16, []byte) {
	seq := c.nextSeq()
	req := &jce.TroopMemberListRequest{
		Uin:       c.Uin,
		GroupCode: groupCode,
		NextUin:   nextUin,
		GroupUin:  groupUin,
		Version:   2,
	}
	b := append([]byte{0x0A}, req.ToBytes()...)
	b = append(b, 0x0B)
	buf := &jce.RequestDataVersion3{
		Map: map[string][]byte{"GTML": b},
	}
	pkt := &jce.RequestPacket{
		IVersion:     3,
		IRequestId:   c.nextPacketSeq(),
		SServantName: "mqq.IMService.FriendListServiceServantObj",
		SFuncName:    "GetTroopMemberListReq",
		SBuffer:      buf.ToBytes(),
		Context:      make(map[string]string),
		Status:       make(map[string]string),
	}
	packet := packets.BuildUniPacket(c.Uin, seq, "friendlist.GetTroopMemberListReq", 1, c.OutGoingPacketSessionId, []byte{}, c.sigInfo.d2Key, pkt.ToBytes())
	return seq, packet
}

// MessageSvc.PbGetMsg
func (c *QQClient) buildGetMessageRequestPacket(flag msg.SyncFlag, msgTime int64) (uint16, []byte) {
	seq := c.nextSeq()
	cook := c.syncCookie
	if cook == nil {
		cook, _ = proto.Marshal(&msg.SyncCookie{
			Time:   msgTime,
			Ran1:   758330138,
			Ran2:   2480149246,
			Const1: 1167238020,
			Const2: 3913056418,
			Const3: 0x1D,
		})
	}
	req := &msg.GetMessageRequest{
		SyncFlag:           flag,
		SyncCookie:         cook,
		LatestRambleNumber: 20,
		OtherRambleNumber:  3,
		OnlineSyncFlag:     1,
		ContextFlag:        1,
		MsgReqType:         1,
		PubaccountCookie:   []byte{},
		MsgCtrlBuf:         []byte{},
		ServerBuf:          []byte{},
	}
	payload, _ := proto.Marshal(req)
	packet := packets.BuildUniPacket(c.Uin, seq, "MessageSvc.PbGetMsg", 1, c.OutGoingPacketSessionId, []byte{}, c.sigInfo.d2Key, payload)
	return seq, packet
}

func (c *QQClient) buildStopGetMessagePacket(msgTime int64) []byte {
	_, pkt := c.buildGetMessageRequestPacket(msg.SyncFlag_STOP, msgTime)
	return pkt
}

// MessageSvc.PbDeleteMsg
func (c *QQClient) buildDeleteMessageRequestPacket(msg []*pb.MessageItem) (uint16, []byte) {
	seq := c.nextSeq()
	req := &pb.DeleteMessageRequest{Items: msg}
	payload, _ := proto.Marshal(req)
	packet := packets.BuildUniPacket(c.Uin, seq, "MessageSvc.PbDeleteMsg", 1, c.OutGoingPacketSessionId, EmptyBytes, c.sigInfo.d2Key, payload)
	return seq, packet
}

// OnlinePush.RespPush
func (c *QQClient) buildDeleteOnlinePushPacket(uin int64, seq uint16, delMsg []jce.PushMessageInfo) []byte {
	req := &jce.SvcRespPushMsg{Uin: uin}
	for _, m := range delMsg {
		req.DelInfos = append(req.DelInfos, &jce.DelMsgInfo{
			FromUin:    m.FromUin,
			MsgSeq:     m.MsgSeq,
			MsgCookies: m.MsgCookies,
			MsgTime:    m.MsgTime,
		})
	}
	b := append([]byte{0x0A}, req.ToBytes()...)
	b = append(b, 0x0B)
	buf := &jce.RequestDataVersion3{
		Map: map[string][]byte{"resp": b},
	}
	pkt := &jce.RequestPacket{
		IVersion:     3,
		IRequestId:   int32(seq),
		SServantName: "OnlinePush",
		SFuncName:    "SvcRespPushMsg",
		SBuffer:      buf.ToBytes(),
		Context:      make(map[string]string),
		Status:       make(map[string]string),
	}
	return packets.BuildUniPacket(c.Uin, seq, "OnlinePush.RespPush", 1, c.OutGoingPacketSessionId, []byte{}, c.sigInfo.d2Key, pkt.ToBytes())
}

// MessageSvc.PbSendMsg
func (c *QQClient) buildGroupSendingPacket(groupCode int64, r int32, forward bool, m *message.SendingMessage) (uint16, []byte) {
	seq := c.nextSeq()
	if m.Ptt != nil {
		m.Elements = []message.IMessageElement{}
	}

	req := &msg.SendMessageRequest{
		RoutingHead: &msg.RoutingHead{Grp: &msg.Grp{GroupCode: groupCode}},
		ContentHead: &msg.ContentHead{PkgNum: 1},
		MsgBody: &msg.MessageBody{
			RichText: &msg.RichText{
				Elems: message.ToProtoElems(m.Elements, true),
				Ptt:   m.Ptt,
			},
		},
		MsgSeq:     c.nextGroupSeq(),
		MsgRand:    r,
		SyncCookie: EmptyBytes,
		MsgVia:     1,
		MsgCtrl: func() *msg.MsgCtrl {
			if forward {
				return &msg.MsgCtrl{MsgFlag: 4}
			}
			return nil
		}(),
	}
	payload, _ := proto.Marshal(req)
	packet := packets.BuildUniPacket(c.Uin, seq, "MessageSvc.PbSendMsg", 1, c.OutGoingPacketSessionId, EmptyBytes, c.sigInfo.d2Key, payload)
	return seq, packet
}

// MessageSvc.PbSendMsg
func (c *QQClient) buildFriendSendingPacket(target int64, msgSeq, r, pkgNum, pkgIndex, pkgDiv int32, time int64, m []message.IMessageElement) (uint16, []byte) {
	seq := c.nextSeq()
	req := &msg.SendMessageRequest{
		RoutingHead: &msg.RoutingHead{C2C: &msg.C2C{ToUin: target}},
		ContentHead: &msg.ContentHead{PkgNum: pkgNum, PkgIndex: pkgIndex, DivSeq: pkgDiv},
		MsgBody: &msg.MessageBody{
			RichText: &msg.RichText{
				Elems: message.ToProtoElems(m, false),
			},
		},
		MsgSeq:  msgSeq,
		MsgRand: r,
		SyncCookie: func() []byte {
			cookie := &msg.SyncCookie{
				Time:   time,
				Ran1:   rand.Int63(),
				Ran2:   rand.Int63(),
				Const1: syncConst1,
				Const2: syncConst2,
				Const3: 0x1d,
			}
			b, _ := proto.Marshal(cookie)
			return b
		}(),
	}
	payload, _ := proto.Marshal(req)
	packet := packets.BuildUniPacket(c.Uin, seq, "MessageSvc.PbSendMsg", 1, c.OutGoingPacketSessionId, EmptyBytes, c.sigInfo.d2Key, payload)
	return seq, packet
}

// LongConn.OffPicUp
func (c *QQClient) buildOffPicUpPacket(target int64, md5 []byte, size int32) (uint16, []byte) {
	seq := c.nextSeq()
	req := &cmd0x352.ReqBody{
		Subcmd: 1,
		MsgTryupImgReq: []*cmd0x352.D352TryUpImgReq{
			{
				SrcUin:       int32(c.Uin),
				DstUin:       int32(target),
				FileMd5:      md5,
				FileSize:     size,
				Filename:     hex.EncodeToString(md5) + ".jpg",
				SrcTerm:      5,
				PlatformType: 9,
				BuType:       1,
				ImgOriginal:  1,
				ImgType:      1000,
				BuildVer:     "8.2.7.4410",
				FileIndex:    EmptyBytes,
				SrvUpload:    1,
				TransferUrl:  EmptyBytes,
			},
		},
	}
	payload, _ := proto.Marshal(req)
	packet := packets.BuildUniPacket(c.Uin, seq, "LongConn.OffPicUp", 1, c.OutGoingPacketSessionId, EmptyBytes, c.sigInfo.d2Key, payload)
	return seq, packet
}

// ImgStore.GroupPicUp
func (c *QQClient) buildGroupImageStorePacket(groupCode int64, md5 []byte, size int32) (uint16, []byte) {
	seq := c.nextSeq()
	name := utils.RandomString(16) + ".gif"
	req := &pb.D388ReqBody{
		NetType: 3,
		Subcmd:  1,
		MsgTryUpImgReq: []*pb.TryUpImgReq{
			{
				GroupCode:    groupCode,
				SrcUin:       c.Uin,
				FileMd5:      md5,
				FileSize:     int64(size),
				FileName:     name,
				SrcTerm:      5,
				PlatformType: 9,
				BuType:       1,
				PicType:      1000,
				BuildVer:     "8.2.7.4410",
				AppPicType:   1006,
				FileIndex:    EmptyBytes,
				TransferUrl:  EmptyBytes,
			},
		},
		Extension: EmptyBytes,
	}
	payload, _ := proto.Marshal(req)
	packet := packets.BuildUniPacket(c.Uin, seq, "ImgStore.GroupPicUp", 1, c.OutGoingPacketSessionId, EmptyBytes, c.sigInfo.d2Key, payload)
	return seq, packet
}

func (c *QQClient) buildImageUploadPacket(data, updKey []byte, commandId int32, fmd5 [16]byte) (r [][]byte) {
	offset := 0
	binary.ToChunkedBytesF(data, 8192*1024, func(chunked []byte) {
		w := binary.NewWriter()
		cmd5 := md5.Sum(chunked)
		head, _ := proto.Marshal(&pb.ReqDataHighwayHead{
			MsgBasehead: &pb.DataHighwayHead{
				Version: 1,
				Uin:     strconv.FormatInt(c.Uin, 10),
				Command: "PicUp.DataUp",
				Seq: func() int32 {
					if commandId == 2 {
						return c.nextGroupDataTransSeq()
					}
					if commandId == 27 {
						return c.nextHighwayApplySeq()
					}
					return c.nextGroupDataTransSeq()
				}(),
				Appid:     537062409,
				Dataflag:  4096,
				CommandId: commandId,
				LocaleId:  2052,
			},
			MsgSeghead: &pb.SegHead{
				Filesize:      int64(len(data)),
				Dataoffset:    int64(offset),
				Datalength:    int32(len(chunked)),
				Serviceticket: updKey,
				Md5:           cmd5[:],
				FileMd5:       fmd5[:],
			},
			ReqExtendinfo: EmptyBytes,
		})
		offset += len(chunked)
		w.WriteByte(40)
		w.WriteUInt32(uint32(len(head)))
		w.WriteUInt32(uint32(len(chunked)))
		w.Write(head)
		w.Write(chunked)
		w.WriteByte(41)
		r = append(r, w.Bytes())
	})
	return
}

// PttStore.GroupPttUp
func (c *QQClient) buildGroupPttStorePacket(groupCode int64, md5 []byte, size, voiceLength int32) (uint16, []byte) {
	seq := c.nextSeq()
	req := &pb.D388ReqBody{
		NetType: 3,
		Subcmd:  3,
		MsgTryUpPttReq: []*pb.TryUpPttReq{
			{
				GroupCode:     groupCode,
				SrcUin:        c.Uin,
				FileMd5:       md5,
				FileSize:      int64(size),
				FileName:      md5,
				SrcTerm:       5,
				PlatformType:  9,
				BuType:        4,
				InnerIp:       0,
				BuildVer:      "6.5.5.663",
				VoiceLength:   voiceLength,
				Codec:         0, // 0->source 1->transcode ?
				VoiceType:     1,
				BoolNewUpChan: true,
			},
		},
		Extension: EmptyBytes,
	}
	payload, _ := proto.Marshal(req)
	packet := packets.BuildUniPacket(c.Uin, seq, "PttStore.GroupPttUp", 1, c.OutGoingPacketSessionId, EmptyBytes, c.sigInfo.d2Key, payload)
	return seq, packet
}

// ProfileService.Pb.ReqSystemMsgNew.Group
func (c *QQClient) buildSystemMsgNewGroupPacket() (uint16, []byte) {
	seq := c.nextSeq()
	req := &structmsg.ReqSystemMsgNew{
		MsgNum:    5,
		Version:   100,
		Checktype: 3,
		Flag: &structmsg.FlagInfo{
			GrpMsgKickAdmin:                   1,
			GrpMsgHiddenGrp:                   1,
			GrpMsgWordingDown:                 1,
			GrpMsgGetOfficialAccount:          1,
			GrpMsgGetPayInGroup:               1,
			FrdMsgDiscuss2ManyChat:            1,
			GrpMsgNotAllowJoinGrpInviteNotFrd: 1,
			FrdMsgNeedWaitingMsg:              1,
			FrdMsgUint32NeedAllUnreadMsg:      1,
			GrpMsgNeedAutoAdminWording:        1,
			GrpMsgGetTransferGroupMsgFlag:     1,
			GrpMsgGetQuitPayGroupMsgFlag:      1,
			GrpMsgSupportInviteAutoJoin:       1,
			GrpMsgMaskInviteAutoJoin:          1,
			GrpMsgGetDisbandedByAdmin:         1,
			GrpMsgGetC2CInviteJoinGroup:       1,
		},
		FriendMsgTypeFlag: 1,
	}
	payload, _ := proto.Marshal(req)
	packet := packets.BuildUniPacket(c.Uin, seq, "ProfileService.Pb.ReqSystemMsgNew.Group", 1, c.OutGoingPacketSessionId, EmptyBytes, c.sigInfo.d2Key, payload)
	return seq, packet
}

// ProfileService.Pb.ReqSystemMsgNew.Friend
func (c *QQClient) buildSystemMsgNewFriendPacket() (uint16, []byte) {
	seq := c.nextSeq()
	req := &structmsg.ReqSystemMsgNew{
		MsgNum:    20,
		Version:   1000,
		Checktype: 2,
		Flag: &structmsg.FlagInfo{
			FrdMsgDiscuss2ManyChat:       1,
			FrdMsgGetBusiCard:            1,
			FrdMsgNeedWaitingMsg:         1,
			FrdMsgUint32NeedAllUnreadMsg: 1,
			GrpMsgMaskInviteAutoJoin:     1,
		},
		FriendMsgTypeFlag: 1,
	}
	payload, _ := proto.Marshal(req)
	packet := packets.BuildUniPacket(c.Uin, seq, "ProfileService.Pb.ReqSystemMsgNew.Friend", 1, c.OutGoingPacketSessionId, EmptyBytes, c.sigInfo.d2Key, payload)
	return seq, packet
}

// ProfileService.Pb.ReqSystemMsgAction.Group
func (c *QQClient) buildSystemMsgGroupActionPacket(reqId, requester, group int64, isInvite, accept, block bool) (uint16, []byte) {
	seq := c.nextSeq()
	req := &structmsg.ReqSystemMsgAction{
		MsgType: 1,
		MsgSeq:  reqId,
		ReqUin:  requester,
		SubType: 1,
		SrcId:   3,
		SubSrcId: func() int32 {
			if isInvite {
				return 10016
			}
			return 31
		}(),
		GroupMsgType: func() int32 {
			if isInvite {
				return 2
			}
			return 1
		}(),
		ActionInfo: &structmsg.SystemMsgActionInfo{
			Type: func() int32 {
				if accept {
					return 11
				}
				return 12
			}(),
			GroupCode: group,
			Blacklist: block,
			Sig:       EmptyBytes,
		},
		Language: 1000,
	}
	payload, _ := proto.Marshal(req)
	packet := packets.BuildUniPacket(c.Uin, seq, "ProfileService.Pb.ReqSystemMsgAction.Group", 1, c.OutGoingPacketSessionId, EmptyBytes, c.sigInfo.d2Key, payload)
	return seq, packet
}

// ProfileService.Pb.ReqSystemMsgAction.Friend
func (c *QQClient) buildSystemMsgFriendActionPacket(reqId, requester int64, accept bool) (uint16, []byte) {
	seq := c.nextSeq()
	req := &structmsg.ReqSystemMsgAction{
		MsgType:  1,
		MsgSeq:   reqId,
		ReqUin:   requester,
		SubType:  1,
		SrcId:    6,
		SubSrcId: 7,
		ActionInfo: &structmsg.SystemMsgActionInfo{
			Type: func() int32 {
				if accept {
					return 2
				}
				return 3
			}(),
			Blacklist:    false,
			AddFrdSNInfo: &structmsg.AddFrdSNInfo{},
		},
	}
	payload, _ := proto.Marshal(req)
	packet := packets.BuildUniPacket(c.Uin, seq, "ProfileService.Pb.ReqSystemMsgAction.Friend", 1, c.OutGoingPacketSessionId, EmptyBytes, c.sigInfo.d2Key, payload)
	return seq, packet
}

// PbMessageSvc.PbMsgWithDraw
func (c *QQClient) buildGroupRecallPacket(groupCode int64, msgSeq, msgRan int32) (uint16, []byte) {
	seq := c.nextSeq()
	req := &msg.MsgWithDrawReq{
		GroupWithDraw: []*msg.GroupMsgWithDrawReq{
			{
				SubCmd:    1,
				GroupCode: groupCode,
				MsgList: []*msg.GroupMsgInfo{
					{
						MsgSeq:    msgSeq,
						MsgRandom: msgRan,
						MsgType:   0,
					},
				},
				UserDef: []byte{0x08, 0x00},
			},
		},
	}
	payload, _ := proto.Marshal(req)
	packet := packets.BuildUniPacket(c.Uin, seq, "PbMessageSvc.PbMsgWithDraw", 1, c.OutGoingPacketSessionId, EmptyBytes, c.sigInfo.d2Key, payload)
	return seq, packet
}

// friendlist.ModifyGroupCardReq
func (c *QQClient) buildEditGroupTagPacket(groupCode, memberUin int64, newTag string) (uint16, []byte) {
	seq := c.nextSeq()
	req := &jce.ModifyGroupCardRequest{
		GroupCode: groupCode,
		UinInfo: []jce.Struct{
			&jce.UinInfo{
				Uin:  memberUin,
				Flag: 31,
				Name: newTag,
			},
		},
	}
	buf := &jce.RequestDataVersion3{Map: map[string][]byte{"MGCREQ": packRequestDataV3(req.ToBytes())}}
	pkt := &jce.RequestPacket{
		IVersion:     3,
		IRequestId:   c.nextPacketSeq(),
		SServantName: "mqq.IMService.FriendListServiceServantObj",
		SFuncName:    "ModifyGroupCardReq",
		SBuffer:      buf.ToBytes(),
		Context:      map[string]string{},
		Status:       map[string]string{},
	}
	packet := packets.BuildUniPacket(c.Uin, seq, "friendlist.ModifyGroupCardReq", 1, c.OutGoingPacketSessionId, EmptyBytes, c.sigInfo.d2Key, pkt.ToBytes())
	return seq, packet
}

// OidbSvc.0x8fc_2
func (c *QQClient) buildEditSpecialTitlePacket(groupCode, memberUin int64, newTitle string) (uint16, []byte) {
	seq := c.nextSeq()
	body := &oidb.D8FCReqBody{
		GroupCode: groupCode,
		MemLevelInfo: []*oidb.D8FCMemberInfo{
			{
				Uin:                    memberUin,
				UinName:                []byte(newTitle),
				SpecialTitle:           []byte(newTitle),
				SpecialTitleExpireTime: -1,
			},
		},
	}
	b, _ := proto.Marshal(body)
	req := &oidb.OIDBSSOPkg{
		Command:     2300,
		ServiceType: 2,
		Bodybuffer:  b,
	}
	payload, _ := proto.Marshal(req)
	packet := packets.BuildUniPacket(c.Uin, seq, "OidbSvc.0x8fc_2", 1, c.OutGoingPacketSessionId, EmptyBytes, c.sigInfo.d2Key, payload)
	return seq, packet
}

// OidbSvc.0x89a_0
func (c *QQClient) buildGroupOperationPacket(body *oidb.D89AReqBody) (uint16, []byte) {
	seq := c.nextSeq()
	b, _ := proto.Marshal(body)
	req := &oidb.OIDBSSOPkg{
		Command:    2202,
		Bodybuffer: b,
	}
	payload, _ := proto.Marshal(req)
	packet := packets.BuildUniPacket(c.Uin, seq, "OidbSvc.0x89a_0", 1, c.OutGoingPacketSessionId, EmptyBytes, c.sigInfo.d2Key, payload)
	return seq, packet
}

// OidbSvc.0x89a_0
func (c *QQClient) buildGroupNameUpdatePacket(groupCode int64, newName string) (uint16, []byte) {
	body := &oidb.D89AReqBody{
		GroupCode: groupCode,
		StGroupInfo: &oidb.D89AGroupinfo{
			IngGroupName: []byte(newName),
		},
	}
	return c.buildGroupOperationPacket(body)
}

// OidbSvc.0x89a_0
func (c *QQClient) buildGroupMuteAllPacket(groupCode int64, mute bool) (uint16, []byte) {
	body := &oidb.D89AReqBody{
		GroupCode: groupCode,
		StGroupInfo: &oidb.D89AGroupinfo{
			ShutupTime: &oidb.D89AGroupinfo_Val{Val: func() int32 {
				if mute {
					return 1
				}
				return 0
			}()},
		},
	}
	return c.buildGroupOperationPacket(body)
}

// OidbSvc.0x8a0_0
func (c *QQClient) buildGroupKickPacket(groupCode, memberUin int64, kickMsg string) (uint16, []byte) {
	seq := c.nextSeq()
	body := &oidb.D8A0ReqBody{
		OptUint64GroupCode: groupCode,
		MsgKickList: []*oidb.D8A0KickMemberInfo{
			{
				OptUint32Operate:   5,
				OptUint64MemberUin: memberUin,
				OptUint32Flag:      1,
			},
		},
		KickMsg: []byte(kickMsg),
	}
	b, _ := proto.Marshal(body)
	req := &oidb.OIDBSSOPkg{
		Command:    2208,
		Bodybuffer: b,
	}
	payload, _ := proto.Marshal(req)
	packet := packets.BuildUniPacket(c.Uin, seq, "OidbSvc.0x8a0_0", 1, c.OutGoingPacketSessionId, EmptyBytes, c.sigInfo.d2Key, payload)
	return seq, packet
}

// OidbSvc.0x570_8
func (c *QQClient) buildGroupMutePacket(groupCode, memberUin int64, time uint32) (uint16, []byte) {
	seq := c.nextSeq()
	req := &oidb.OIDBSSOPkg{
		Command:     1392,
		ServiceType: 8,
		Bodybuffer: binary.NewWriterF(func(w *binary.Writer) {
			w.WriteUInt32(uint32(groupCode))
			w.WriteByte(32)
			w.WriteUInt16(1)
			w.WriteUInt32(uint32(memberUin))
			w.WriteUInt32(time)
		}),
	}
	payload, _ := proto.Marshal(req)
	packet := packets.BuildUniPacket(c.Uin, seq, "OidbSvc.0x570_8", 1, c.OutGoingPacketSessionId, EmptyBytes, c.sigInfo.d2Key, payload)
	return seq, packet
}

// MultiMsg.ApplyUp
func (c *QQClient) buildMultiApplyUpPacket(data, hash []byte, buType int32, groupUin int64) (uint16, []byte) {
	seq := c.nextSeq()
	req := &multimsg.MultiReqBody{
		Subcmd:       1,
		TermType:     5,
		PlatformType: 9,
		NetType:      3,
		BuildVer:     "8.2.0.1296",
		MultimsgApplyupReq: []*multimsg.MultiMsgApplyUpReq{
			{
				DstUin:  groupUin,
				MsgSize: int64(len(data)),
				MsgMd5:  hash,
				MsgType: 3,
			},
		},
		BuType: buType,
	}
	payload, _ := proto.Marshal(req)
	packet := packets.BuildUniPacket(c.Uin, seq, "MultiMsg.ApplyUp", 1, c.OutGoingPacketSessionId, EmptyBytes, c.sigInfo.d2Key, payload)
	return seq, packet
}

// MultiMsg.ApplyDown
func (c *QQClient) buildMultiApplyDownPacket(resId string) (uint16, []byte) {
	seq := c.nextSeq()
	req := &multimsg.MultiReqBody{
		Subcmd:       2,
		TermType:     5,
		PlatformType: 9,
		NetType:      3,
		BuildVer:     "8.2.0.1296",
		MultimsgApplydownReq: []*multimsg.MultiMsgApplyDownReq{
			{
				MsgResid: []byte(resId),
				MsgType:  3,
			},
		},
		BuType:         2,
		ReqChannelType: 2,
	}
	payload, _ := proto.Marshal(req)
	packet := packets.BuildUniPacket(c.Uin, seq, "MultiMsg.ApplyDown", 1, c.OutGoingPacketSessionId, EmptyBytes, c.sigInfo.d2Key, payload)
	return seq, packet
}

// ProfileService.GroupMngReq
func (c *QQClient) buildQuitGroupPacket(groupCode int64) (uint16, []byte) {
	seq := c.nextSeq()
	jw := jce.NewJceWriter()
	jw.WriteInt32(2, 0)
	jw.WriteInt64(c.Uin, 1)
	jw.WriteBytes(binary.NewWriterF(func(w *binary.Writer) {
		w.WriteUInt32(uint32(c.Uin))
		w.WriteUInt32(uint32(groupCode))
	}), 2)
	buf := &jce.RequestDataVersion3{Map: map[string][]byte{"GroupMngReq": packRequestDataV3(jw.Bytes())}}
	pkt := &jce.RequestPacket{
		IVersion:     3,
		IRequestId:   c.nextPacketSeq(),
		SServantName: "KQQ.ProfileService.ProfileServantObj",
		SFuncName:    "GroupMngReq",
		SBuffer:      buf.ToBytes(),
		Context:      map[string]string{},
		Status:       map[string]string{},
	}
	packet := packets.BuildUniPacket(c.Uin, seq, "ProfileService.GroupMngReq", 1, c.OutGoingPacketSessionId, EmptyBytes, c.sigInfo.d2Key, pkt.ToBytes())
	return seq, packet
}

// OidbSvc.0x6d6_2
func (c *QQClient) buildGroupFileDownloadReqPacket(groupCode int64, fileId string, busId int32) (uint16, []byte) {
	seq := c.nextSeq()
	body := &oidb.D6D6ReqBody{
		DownloadFileReq: &oidb.DownloadFileReqBody{
			GroupCode: groupCode,
			AppId:     3,
			BusId:     busId,
			FileId:    fileId,
		},
	}
	b, _ := proto.Marshal(body)
	req := &oidb.OIDBSSOPkg{
		Command:     1750,
		ServiceType: 2,
		Bodybuffer:  b,
	}
	payload, _ := proto.Marshal(req)
	packet := packets.BuildUniPacket(c.Uin, seq, "OidbSvc.0x6d6_2", 1, c.OutGoingPacketSessionId, EmptyBytes, c.sigInfo.d2Key, payload)
	return seq, packet
}

// PttCenterSvr.ShortVideoDownReq
func (c *QQClient) buildPttShortVideoDownReqPacket(uuid, md5 []byte) (uint16, []byte) {
	seq := c.nextSeq()
	body := &pttcenter.ShortVideoReqBody{
		Cmd: 400,
		Seq: int32(seq),
		PttShortVideoDownloadReq: &pttcenter.ShortVideoDownloadReq{
			FromUin:      c.Uin,
			ToUin:        c.Uin,
			ChatType:     1,
			ClientType:   7,
			FileId:       string(uuid),
			GroupCode:    1,
			FileMd5:      md5,
			BusinessType: 1,
			FileType:     2,
			DownType:     2,
			SceneType:    2,
		},
	}
	payload, _ := proto.Marshal(body)
	packet := packets.BuildUniPacket(c.Uin, seq, "PttCenterSvr.ShortVideoDownReq", 1, c.OutGoingPacketSessionId, EmptyBytes, c.sigInfo.d2Key, payload)
	return seq, packet
}
