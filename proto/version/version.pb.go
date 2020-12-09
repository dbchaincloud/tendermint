// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: proto/version/version.proto

package version

import (
	bytes "bytes"
	fmt "fmt"
	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/gogo/protobuf/proto"
	math "math"
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

// App includes the protocol and software version for the application.
// This information is included in ResponseInfo. The App.Protocol can be
// updated in ResponseEndBlock.
type App struct {
	Protocol             uint64   `protobuf:"varint,1,opt,name=protocol,proto3" json:"protocol,omitempty"`
	Software             string   `protobuf:"bytes,2,opt,name=software,proto3" json:"software,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *App) Reset()         { *m = App{} }
func (m *App) String() string { return proto.CompactTextString(m) }
func (*App) ProtoMessage()    {}
func (*App) Descriptor() ([]byte, []int) {
	return fileDescriptor_14aa2353622f11e1, []int{0}
}
func (m *App) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_App.Unmarshal(m, b)
}
func (m *App) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_App.Marshal(b, m, deterministic)
}
func (m *App) XXX_Merge(src proto.Message) {
	xxx_messageInfo_App.Merge(m, src)
}
func (m *App) XXX_Size() int {
	return xxx_messageInfo_App.Size(m)
}
func (m *App) XXX_DiscardUnknown() {
	xxx_messageInfo_App.DiscardUnknown(m)
}

var xxx_messageInfo_App proto.InternalMessageInfo

func (m *App) GetProtocol() uint64 {
	if m != nil {
		return m.Protocol
	}
	return 0
}

func (m *App) GetSoftware() string {
	if m != nil {
		return m.Software
	}
	return ""
}

// Consensus captures the consensus rules for processing a block in the blockchain,
// including all blockchain data structures and the rules of the application's
// state transition machine.
type Consensus struct {
	Block                uint64   `protobuf:"varint,1,opt,name=block,proto3" json:"block,omitempty"`
	App                  uint64   `protobuf:"varint,2,opt,name=app,proto3" json:"app,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Consensus) Reset()         { *m = Consensus{} }
func (m *Consensus) String() string { return proto.CompactTextString(m) }
func (*Consensus) ProtoMessage()    {}
func (*Consensus) Descriptor() ([]byte, []int) {
	return fileDescriptor_14aa2353622f11e1, []int{1}
}
func (m *Consensus) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Consensus.Unmarshal(m, b)
}
func (m *Consensus) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Consensus.Marshal(b, m, deterministic)
}
func (m *Consensus) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Consensus.Merge(m, src)
}
func (m *Consensus) XXX_Size() int {
	return xxx_messageInfo_Consensus.Size(m)
}
func (m *Consensus) XXX_DiscardUnknown() {
	xxx_messageInfo_Consensus.DiscardUnknown(m)
}

var xxx_messageInfo_Consensus proto.InternalMessageInfo

func (m *Consensus) GetBlock() uint64 {
	if m != nil {
		return m.Block
	}
	return 0
}

func (m *Consensus) GetApp() uint64 {
	if m != nil {
		return m.App
	}
	return 0
}

func init() {
	proto.RegisterType((*App)(nil), "tendermint.proto.version.App")
	proto.RegisterType((*Consensus)(nil), "tendermint.proto.version.Consensus")
}

func init() { proto.RegisterFile("proto/version/version.proto", fileDescriptor_14aa2353622f11e1) }

var fileDescriptor_14aa2353622f11e1 = []byte{
	// 211 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0x92, 0x2e, 0x28, 0xca, 0x2f,
	0xc9, 0xd7, 0x2f, 0x4b, 0x2d, 0x2a, 0xce, 0xcc, 0xcf, 0x83, 0xd1, 0x7a, 0x60, 0x51, 0x21, 0x89,
	0x92, 0xd4, 0xbc, 0x94, 0xd4, 0xa2, 0xdc, 0xcc, 0xbc, 0x12, 0x88, 0x88, 0x1e, 0x54, 0x5e, 0x4a,
	0xad, 0x24, 0x23, 0xb3, 0x28, 0x25, 0xbe, 0x20, 0xb1, 0xa8, 0xa4, 0x52, 0x1f, 0x62, 0x44, 0x7a,
	0x7e, 0x7a, 0x3e, 0x82, 0x05, 0x51, 0xaf, 0x64, 0xcb, 0xc5, 0xec, 0x58, 0x50, 0x20, 0x24, 0xc5,
	0xc5, 0x01, 0xe6, 0x27, 0xe7, 0xe7, 0x48, 0x30, 0x2a, 0x30, 0x6a, 0xb0, 0x04, 0xc1, 0xf9, 0x20,
	0xb9, 0xe2, 0xfc, 0xb4, 0x92, 0xf2, 0xc4, 0xa2, 0x54, 0x09, 0x26, 0x05, 0x46, 0x0d, 0xce, 0x20,
	0x38, 0x5f, 0xc9, 0x92, 0x8b, 0xd3, 0x39, 0x3f, 0xaf, 0x38, 0x35, 0xaf, 0xb8, 0xb4, 0x58, 0x48,
	0x84, 0x8b, 0x35, 0x29, 0x27, 0x3f, 0x39, 0x1b, 0x6a, 0x02, 0x84, 0x23, 0x24, 0xc0, 0xc5, 0x9c,
	0x58, 0x50, 0x00, 0xd6, 0xc9, 0x12, 0x04, 0x62, 0x5a, 0xb1, 0xbc, 0x58, 0x20, 0xcf, 0xe8, 0x64,
	0x14, 0x65, 0x90, 0x9e, 0x59, 0x92, 0x51, 0x9a, 0xa4, 0x97, 0x9c, 0x9f, 0xab, 0x9f, 0x92, 0x94,
	0x9c, 0x91, 0x98, 0x99, 0x97, 0x9c, 0x93, 0x5f, 0x9a, 0xa2, 0x8f, 0xf0, 0x95, 0x3e, 0x8a, 0xef,
	0x93, 0xd8, 0xc0, 0x5c, 0x63, 0x40, 0x00, 0x00, 0x00, 0xff, 0xff, 0x0a, 0x6d, 0x24, 0xaf, 0x15,
	0x01, 0x00, 0x00,
}

func (this *Consensus) Equal(that interface{}) bool {
	if that == nil {
		return this == nil
	}

	that1, ok := that.(*Consensus)
	if !ok {
		that2, ok := that.(Consensus)
		if ok {
			that1 = &that2
		} else {
			return false
		}
	}
	if that1 == nil {
		return this == nil
	} else if this == nil {
		return false
	}
	if this.Block != that1.Block {
		return false
	}
	if this.App != that1.App {
		return false
	}
	if !bytes.Equal(this.XXX_unrecognized, that1.XXX_unrecognized) {
		return false
	}
	return true
}
