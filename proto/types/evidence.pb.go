// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: proto/types/evidence.proto

package types

import (
	fmt "fmt"
	keys "github.com/dbchaincloud/tendermint/proto/crypto/keys"
	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/gogo/protobuf/proto"
	_ "github.com/golang/protobuf/ptypes/timestamp"
	math "math"
	time "time"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf
var _ = time.Kitchen

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion3 // please upgrade the proto package

// DuplicateVoteEvidence contains evidence a validator signed two conflicting
// votes.
type DuplicateVoteEvidence struct {
	PubKey               *keys.PublicKey `protobuf:"bytes,1,opt,name=pub_key,json=pubKey,proto3" json:"pub_key,omitempty"`
	VoteA                *Vote           `protobuf:"bytes,2,opt,name=vote_a,json=voteA,proto3" json:"vote_a,omitempty"`
	VoteB                *Vote           `protobuf:"bytes,3,opt,name=vote_b,json=voteB,proto3" json:"vote_b,omitempty"`
	XXX_NoUnkeyedLiteral struct{}        `json:"-"`
	XXX_unrecognized     []byte          `json:"-"`
	XXX_sizecache        int32           `json:"-"`
}

func (m *DuplicateVoteEvidence) Reset()         { *m = DuplicateVoteEvidence{} }
func (m *DuplicateVoteEvidence) String() string { return proto.CompactTextString(m) }
func (*DuplicateVoteEvidence) ProtoMessage()    {}
func (*DuplicateVoteEvidence) Descriptor() ([]byte, []int) {
	return fileDescriptor_86495eef24aeacc0, []int{0}
}
func (m *DuplicateVoteEvidence) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_DuplicateVoteEvidence.Unmarshal(m, b)
}
func (m *DuplicateVoteEvidence) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_DuplicateVoteEvidence.Marshal(b, m, deterministic)
}
func (m *DuplicateVoteEvidence) XXX_Merge(src proto.Message) {
	xxx_messageInfo_DuplicateVoteEvidence.Merge(m, src)
}
func (m *DuplicateVoteEvidence) XXX_Size() int {
	return xxx_messageInfo_DuplicateVoteEvidence.Size(m)
}
func (m *DuplicateVoteEvidence) XXX_DiscardUnknown() {
	xxx_messageInfo_DuplicateVoteEvidence.DiscardUnknown(m)
}

var xxx_messageInfo_DuplicateVoteEvidence proto.InternalMessageInfo

func (m *DuplicateVoteEvidence) GetPubKey() *keys.PublicKey {
	if m != nil {
		return m.PubKey
	}
	return nil
}

func (m *DuplicateVoteEvidence) GetVoteA() *Vote {
	if m != nil {
		return m.VoteA
	}
	return nil
}

func (m *DuplicateVoteEvidence) GetVoteB() *Vote {
	if m != nil {
		return m.VoteB
	}
	return nil
}

type PotentialAmnesiaEvidence struct {
	VoteA                *Vote    `protobuf:"bytes,1,opt,name=vote_a,json=voteA,proto3" json:"vote_a,omitempty"`
	VoteB                *Vote    `protobuf:"bytes,2,opt,name=vote_b,json=voteB,proto3" json:"vote_b,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *PotentialAmnesiaEvidence) Reset()         { *m = PotentialAmnesiaEvidence{} }
func (m *PotentialAmnesiaEvidence) String() string { return proto.CompactTextString(m) }
func (*PotentialAmnesiaEvidence) ProtoMessage()    {}
func (*PotentialAmnesiaEvidence) Descriptor() ([]byte, []int) {
	return fileDescriptor_86495eef24aeacc0, []int{1}
}
func (m *PotentialAmnesiaEvidence) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_PotentialAmnesiaEvidence.Unmarshal(m, b)
}
func (m *PotentialAmnesiaEvidence) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_PotentialAmnesiaEvidence.Marshal(b, m, deterministic)
}
func (m *PotentialAmnesiaEvidence) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PotentialAmnesiaEvidence.Merge(m, src)
}
func (m *PotentialAmnesiaEvidence) XXX_Size() int {
	return xxx_messageInfo_PotentialAmnesiaEvidence.Size(m)
}
func (m *PotentialAmnesiaEvidence) XXX_DiscardUnknown() {
	xxx_messageInfo_PotentialAmnesiaEvidence.DiscardUnknown(m)
}

var xxx_messageInfo_PotentialAmnesiaEvidence proto.InternalMessageInfo

func (m *PotentialAmnesiaEvidence) GetVoteA() *Vote {
	if m != nil {
		return m.VoteA
	}
	return nil
}

func (m *PotentialAmnesiaEvidence) GetVoteB() *Vote {
	if m != nil {
		return m.VoteB
	}
	return nil
}

// MockEvidence is used for testing pruposes
type MockEvidence struct {
	EvidenceHeight       int64     `protobuf:"varint,1,opt,name=evidence_height,json=evidenceHeight,proto3" json:"evidence_height,omitempty"`
	EvidenceTime         time.Time `protobuf:"bytes,2,opt,name=evidence_time,json=evidenceTime,proto3,stdtime" json:"evidence_time"`
	EvidenceAddress      []byte    `protobuf:"bytes,3,opt,name=evidence_address,json=evidenceAddress,proto3" json:"evidence_address,omitempty"`
	XXX_NoUnkeyedLiteral struct{}  `json:"-"`
	XXX_unrecognized     []byte    `json:"-"`
	XXX_sizecache        int32     `json:"-"`
}

func (m *MockEvidence) Reset()         { *m = MockEvidence{} }
func (m *MockEvidence) String() string { return proto.CompactTextString(m) }
func (*MockEvidence) ProtoMessage()    {}
func (*MockEvidence) Descriptor() ([]byte, []int) {
	return fileDescriptor_86495eef24aeacc0, []int{2}
}
func (m *MockEvidence) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_MockEvidence.Unmarshal(m, b)
}
func (m *MockEvidence) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_MockEvidence.Marshal(b, m, deterministic)
}
func (m *MockEvidence) XXX_Merge(src proto.Message) {
	xxx_messageInfo_MockEvidence.Merge(m, src)
}
func (m *MockEvidence) XXX_Size() int {
	return xxx_messageInfo_MockEvidence.Size(m)
}
func (m *MockEvidence) XXX_DiscardUnknown() {
	xxx_messageInfo_MockEvidence.DiscardUnknown(m)
}

var xxx_messageInfo_MockEvidence proto.InternalMessageInfo

func (m *MockEvidence) GetEvidenceHeight() int64 {
	if m != nil {
		return m.EvidenceHeight
	}
	return 0
}

func (m *MockEvidence) GetEvidenceTime() time.Time {
	if m != nil {
		return m.EvidenceTime
	}
	return time.Time{}
}

func (m *MockEvidence) GetEvidenceAddress() []byte {
	if m != nil {
		return m.EvidenceAddress
	}
	return nil
}

type MockRandomEvidence struct {
	EvidenceHeight       int64     `protobuf:"varint,1,opt,name=evidence_height,json=evidenceHeight,proto3" json:"evidence_height,omitempty"`
	EvidenceTime         time.Time `protobuf:"bytes,2,opt,name=evidence_time,json=evidenceTime,proto3,stdtime" json:"evidence_time"`
	EvidenceAddress      []byte    `protobuf:"bytes,3,opt,name=evidence_address,json=evidenceAddress,proto3" json:"evidence_address,omitempty"`
	RandBytes            []byte    `protobuf:"bytes,4,opt,name=rand_bytes,json=randBytes,proto3" json:"rand_bytes,omitempty"`
	XXX_NoUnkeyedLiteral struct{}  `json:"-"`
	XXX_unrecognized     []byte    `json:"-"`
	XXX_sizecache        int32     `json:"-"`
}

func (m *MockRandomEvidence) Reset()         { *m = MockRandomEvidence{} }
func (m *MockRandomEvidence) String() string { return proto.CompactTextString(m) }
func (*MockRandomEvidence) ProtoMessage()    {}
func (*MockRandomEvidence) Descriptor() ([]byte, []int) {
	return fileDescriptor_86495eef24aeacc0, []int{3}
}
func (m *MockRandomEvidence) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_MockRandomEvidence.Unmarshal(m, b)
}
func (m *MockRandomEvidence) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_MockRandomEvidence.Marshal(b, m, deterministic)
}
func (m *MockRandomEvidence) XXX_Merge(src proto.Message) {
	xxx_messageInfo_MockRandomEvidence.Merge(m, src)
}
func (m *MockRandomEvidence) XXX_Size() int {
	return xxx_messageInfo_MockRandomEvidence.Size(m)
}
func (m *MockRandomEvidence) XXX_DiscardUnknown() {
	xxx_messageInfo_MockRandomEvidence.DiscardUnknown(m)
}

var xxx_messageInfo_MockRandomEvidence proto.InternalMessageInfo

func (m *MockRandomEvidence) GetEvidenceHeight() int64 {
	if m != nil {
		return m.EvidenceHeight
	}
	return 0
}

func (m *MockRandomEvidence) GetEvidenceTime() time.Time {
	if m != nil {
		return m.EvidenceTime
	}
	return time.Time{}
}

func (m *MockRandomEvidence) GetEvidenceAddress() []byte {
	if m != nil {
		return m.EvidenceAddress
	}
	return nil
}

func (m *MockRandomEvidence) GetRandBytes() []byte {
	if m != nil {
		return m.RandBytes
	}
	return nil
}

type ConflictingHeadersEvidence struct {
	H1                   *SignedHeader `protobuf:"bytes,1,opt,name=h1,proto3" json:"h1,omitempty"`
	H2                   *SignedHeader `protobuf:"bytes,2,opt,name=h2,proto3" json:"h2,omitempty"`
	XXX_NoUnkeyedLiteral struct{}      `json:"-"`
	XXX_unrecognized     []byte        `json:"-"`
	XXX_sizecache        int32         `json:"-"`
}

func (m *ConflictingHeadersEvidence) Reset()         { *m = ConflictingHeadersEvidence{} }
func (m *ConflictingHeadersEvidence) String() string { return proto.CompactTextString(m) }
func (*ConflictingHeadersEvidence) ProtoMessage()    {}
func (*ConflictingHeadersEvidence) Descriptor() ([]byte, []int) {
	return fileDescriptor_86495eef24aeacc0, []int{4}
}
func (m *ConflictingHeadersEvidence) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ConflictingHeadersEvidence.Unmarshal(m, b)
}
func (m *ConflictingHeadersEvidence) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ConflictingHeadersEvidence.Marshal(b, m, deterministic)
}
func (m *ConflictingHeadersEvidence) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ConflictingHeadersEvidence.Merge(m, src)
}
func (m *ConflictingHeadersEvidence) XXX_Size() int {
	return xxx_messageInfo_ConflictingHeadersEvidence.Size(m)
}
func (m *ConflictingHeadersEvidence) XXX_DiscardUnknown() {
	xxx_messageInfo_ConflictingHeadersEvidence.DiscardUnknown(m)
}

var xxx_messageInfo_ConflictingHeadersEvidence proto.InternalMessageInfo

func (m *ConflictingHeadersEvidence) GetH1() *SignedHeader {
	if m != nil {
		return m.H1
	}
	return nil
}

func (m *ConflictingHeadersEvidence) GetH2() *SignedHeader {
	if m != nil {
		return m.H2
	}
	return nil
}

type LunaticValidatorEvidence struct {
	Header               *Header  `protobuf:"bytes,1,opt,name=header,proto3" json:"header,omitempty"`
	Vote                 *Vote    `protobuf:"bytes,2,opt,name=vote,proto3" json:"vote,omitempty"`
	InvalidHeaderField   string   `protobuf:"bytes,3,opt,name=invalid_header_field,json=invalidHeaderField,proto3" json:"invalid_header_field,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *LunaticValidatorEvidence) Reset()         { *m = LunaticValidatorEvidence{} }
func (m *LunaticValidatorEvidence) String() string { return proto.CompactTextString(m) }
func (*LunaticValidatorEvidence) ProtoMessage()    {}
func (*LunaticValidatorEvidence) Descriptor() ([]byte, []int) {
	return fileDescriptor_86495eef24aeacc0, []int{5}
}
func (m *LunaticValidatorEvidence) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_LunaticValidatorEvidence.Unmarshal(m, b)
}
func (m *LunaticValidatorEvidence) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_LunaticValidatorEvidence.Marshal(b, m, deterministic)
}
func (m *LunaticValidatorEvidence) XXX_Merge(src proto.Message) {
	xxx_messageInfo_LunaticValidatorEvidence.Merge(m, src)
}
func (m *LunaticValidatorEvidence) XXX_Size() int {
	return xxx_messageInfo_LunaticValidatorEvidence.Size(m)
}
func (m *LunaticValidatorEvidence) XXX_DiscardUnknown() {
	xxx_messageInfo_LunaticValidatorEvidence.DiscardUnknown(m)
}

var xxx_messageInfo_LunaticValidatorEvidence proto.InternalMessageInfo

func (m *LunaticValidatorEvidence) GetHeader() *Header {
	if m != nil {
		return m.Header
	}
	return nil
}

func (m *LunaticValidatorEvidence) GetVote() *Vote {
	if m != nil {
		return m.Vote
	}
	return nil
}

func (m *LunaticValidatorEvidence) GetInvalidHeaderField() string {
	if m != nil {
		return m.InvalidHeaderField
	}
	return ""
}

type Evidence struct {
	// Types that are valid to be assigned to Sum:
	//	*Evidence_DuplicateVoteEvidence
	//	*Evidence_ConflictingHeadersEvidence
	//	*Evidence_LunaticValidatorEvidence
	//	*Evidence_PotentialAmnesiaEvidence
	//	*Evidence_MockEvidence
	//	*Evidence_MockRandomEvidence
	Sum                  isEvidence_Sum `protobuf_oneof:"sum"`
	XXX_NoUnkeyedLiteral struct{}       `json:"-"`
	XXX_unrecognized     []byte         `json:"-"`
	XXX_sizecache        int32          `json:"-"`
}

func (m *Evidence) Reset()         { *m = Evidence{} }
func (m *Evidence) String() string { return proto.CompactTextString(m) }
func (*Evidence) ProtoMessage()    {}
func (*Evidence) Descriptor() ([]byte, []int) {
	return fileDescriptor_86495eef24aeacc0, []int{6}
}
func (m *Evidence) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Evidence.Unmarshal(m, b)
}
func (m *Evidence) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Evidence.Marshal(b, m, deterministic)
}
func (m *Evidence) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Evidence.Merge(m, src)
}
func (m *Evidence) XXX_Size() int {
	return xxx_messageInfo_Evidence.Size(m)
}
func (m *Evidence) XXX_DiscardUnknown() {
	xxx_messageInfo_Evidence.DiscardUnknown(m)
}

var xxx_messageInfo_Evidence proto.InternalMessageInfo

type isEvidence_Sum interface {
	isEvidence_Sum()
}

type Evidence_DuplicateVoteEvidence struct {
	DuplicateVoteEvidence *DuplicateVoteEvidence `protobuf:"bytes,1,opt,name=duplicate_vote_evidence,json=duplicateVoteEvidence,proto3,oneof" json:"duplicate_vote_evidence,omitempty"`
}
type Evidence_ConflictingHeadersEvidence struct {
	ConflictingHeadersEvidence *ConflictingHeadersEvidence `protobuf:"bytes,2,opt,name=conflicting_headers_evidence,json=conflictingHeadersEvidence,proto3,oneof" json:"conflicting_headers_evidence,omitempty"`
}
type Evidence_LunaticValidatorEvidence struct {
	LunaticValidatorEvidence *LunaticValidatorEvidence `protobuf:"bytes,3,opt,name=lunatic_validator_evidence,json=lunaticValidatorEvidence,proto3,oneof" json:"lunatic_validator_evidence,omitempty"`
}
type Evidence_PotentialAmnesiaEvidence struct {
	PotentialAmnesiaEvidence *PotentialAmnesiaEvidence `protobuf:"bytes,4,opt,name=potential_amnesia_evidence,json=potentialAmnesiaEvidence,proto3,oneof" json:"potential_amnesia_evidence,omitempty"`
}
type Evidence_MockEvidence struct {
	MockEvidence *MockEvidence `protobuf:"bytes,5,opt,name=mock_evidence,json=mockEvidence,proto3,oneof" json:"mock_evidence,omitempty"`
}
type Evidence_MockRandomEvidence struct {
	MockRandomEvidence *MockRandomEvidence `protobuf:"bytes,6,opt,name=mock_random_evidence,json=mockRandomEvidence,proto3,oneof" json:"mock_random_evidence,omitempty"`
}

func (*Evidence_DuplicateVoteEvidence) isEvidence_Sum()      {}
func (*Evidence_ConflictingHeadersEvidence) isEvidence_Sum() {}
func (*Evidence_LunaticValidatorEvidence) isEvidence_Sum()   {}
func (*Evidence_PotentialAmnesiaEvidence) isEvidence_Sum()   {}
func (*Evidence_MockEvidence) isEvidence_Sum()               {}
func (*Evidence_MockRandomEvidence) isEvidence_Sum()         {}

func (m *Evidence) GetSum() isEvidence_Sum {
	if m != nil {
		return m.Sum
	}
	return nil
}

func (m *Evidence) GetDuplicateVoteEvidence() *DuplicateVoteEvidence {
	if x, ok := m.GetSum().(*Evidence_DuplicateVoteEvidence); ok {
		return x.DuplicateVoteEvidence
	}
	return nil
}

func (m *Evidence) GetConflictingHeadersEvidence() *ConflictingHeadersEvidence {
	if x, ok := m.GetSum().(*Evidence_ConflictingHeadersEvidence); ok {
		return x.ConflictingHeadersEvidence
	}
	return nil
}

func (m *Evidence) GetLunaticValidatorEvidence() *LunaticValidatorEvidence {
	if x, ok := m.GetSum().(*Evidence_LunaticValidatorEvidence); ok {
		return x.LunaticValidatorEvidence
	}
	return nil
}

func (m *Evidence) GetPotentialAmnesiaEvidence() *PotentialAmnesiaEvidence {
	if x, ok := m.GetSum().(*Evidence_PotentialAmnesiaEvidence); ok {
		return x.PotentialAmnesiaEvidence
	}
	return nil
}

func (m *Evidence) GetMockEvidence() *MockEvidence {
	if x, ok := m.GetSum().(*Evidence_MockEvidence); ok {
		return x.MockEvidence
	}
	return nil
}

func (m *Evidence) GetMockRandomEvidence() *MockRandomEvidence {
	if x, ok := m.GetSum().(*Evidence_MockRandomEvidence); ok {
		return x.MockRandomEvidence
	}
	return nil
}

// XXX_OneofWrappers is for the internal use of the proto package.
func (*Evidence) XXX_OneofWrappers() []interface{} {
	return []interface{}{
		(*Evidence_DuplicateVoteEvidence)(nil),
		(*Evidence_ConflictingHeadersEvidence)(nil),
		(*Evidence_LunaticValidatorEvidence)(nil),
		(*Evidence_PotentialAmnesiaEvidence)(nil),
		(*Evidence_MockEvidence)(nil),
		(*Evidence_MockRandomEvidence)(nil),
	}
}

// EvidenceData contains any evidence of malicious wrong-doing by validators
type EvidenceData struct {
	Evidence             []Evidence `protobuf:"bytes,1,rep,name=evidence,proto3" json:"evidence"`
	Hash                 []byte     `protobuf:"bytes,2,opt,name=hash,proto3" json:"hash,omitempty"`
	XXX_NoUnkeyedLiteral struct{}   `json:"-"`
	XXX_unrecognized     []byte     `json:"-"`
	XXX_sizecache        int32      `json:"-"`
}

func (m *EvidenceData) Reset()         { *m = EvidenceData{} }
func (m *EvidenceData) String() string { return proto.CompactTextString(m) }
func (*EvidenceData) ProtoMessage()    {}
func (*EvidenceData) Descriptor() ([]byte, []int) {
	return fileDescriptor_86495eef24aeacc0, []int{7}
}
func (m *EvidenceData) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_EvidenceData.Unmarshal(m, b)
}
func (m *EvidenceData) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_EvidenceData.Marshal(b, m, deterministic)
}
func (m *EvidenceData) XXX_Merge(src proto.Message) {
	xxx_messageInfo_EvidenceData.Merge(m, src)
}
func (m *EvidenceData) XXX_Size() int {
	return xxx_messageInfo_EvidenceData.Size(m)
}
func (m *EvidenceData) XXX_DiscardUnknown() {
	xxx_messageInfo_EvidenceData.DiscardUnknown(m)
}

var xxx_messageInfo_EvidenceData proto.InternalMessageInfo

func (m *EvidenceData) GetEvidence() []Evidence {
	if m != nil {
		return m.Evidence
	}
	return nil
}

func (m *EvidenceData) GetHash() []byte {
	if m != nil {
		return m.Hash
	}
	return nil
}

type ProofOfLockChange struct {
	Votes                []Vote         `protobuf:"bytes,1,rep,name=votes,proto3" json:"votes"`
	PubKey               keys.PublicKey `protobuf:"bytes,2,opt,name=pub_key,json=pubKey,proto3" json:"pub_key"`
	XXX_NoUnkeyedLiteral struct{}       `json:"-"`
	XXX_unrecognized     []byte         `json:"-"`
	XXX_sizecache        int32          `json:"-"`
}

func (m *ProofOfLockChange) Reset()         { *m = ProofOfLockChange{} }
func (m *ProofOfLockChange) String() string { return proto.CompactTextString(m) }
func (*ProofOfLockChange) ProtoMessage()    {}
func (*ProofOfLockChange) Descriptor() ([]byte, []int) {
	return fileDescriptor_86495eef24aeacc0, []int{8}
}
func (m *ProofOfLockChange) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ProofOfLockChange.Unmarshal(m, b)
}
func (m *ProofOfLockChange) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ProofOfLockChange.Marshal(b, m, deterministic)
}
func (m *ProofOfLockChange) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ProofOfLockChange.Merge(m, src)
}
func (m *ProofOfLockChange) XXX_Size() int {
	return xxx_messageInfo_ProofOfLockChange.Size(m)
}
func (m *ProofOfLockChange) XXX_DiscardUnknown() {
	xxx_messageInfo_ProofOfLockChange.DiscardUnknown(m)
}

var xxx_messageInfo_ProofOfLockChange proto.InternalMessageInfo

func (m *ProofOfLockChange) GetVotes() []Vote {
	if m != nil {
		return m.Votes
	}
	return nil
}

func (m *ProofOfLockChange) GetPubKey() keys.PublicKey {
	if m != nil {
		return m.PubKey
	}
	return keys.PublicKey{}
}

func init() {
	proto.RegisterType((*DuplicateVoteEvidence)(nil), "tendermint.proto.types.DuplicateVoteEvidence")
	proto.RegisterType((*PotentialAmnesiaEvidence)(nil), "tendermint.proto.types.PotentialAmnesiaEvidence")
	proto.RegisterType((*MockEvidence)(nil), "tendermint.proto.types.MockEvidence")
	proto.RegisterType((*MockRandomEvidence)(nil), "tendermint.proto.types.MockRandomEvidence")
	proto.RegisterType((*ConflictingHeadersEvidence)(nil), "tendermint.proto.types.ConflictingHeadersEvidence")
	proto.RegisterType((*LunaticValidatorEvidence)(nil), "tendermint.proto.types.LunaticValidatorEvidence")
	proto.RegisterType((*Evidence)(nil), "tendermint.proto.types.Evidence")
	proto.RegisterType((*EvidenceData)(nil), "tendermint.proto.types.EvidenceData")
	proto.RegisterType((*ProofOfLockChange)(nil), "tendermint.proto.types.ProofOfLockChange")
}

func init() { proto.RegisterFile("proto/types/evidence.proto", fileDescriptor_86495eef24aeacc0) }

var fileDescriptor_86495eef24aeacc0 = []byte{
	// 792 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xd4, 0x56, 0xcb, 0x6e, 0xdb, 0x46,
	0x14, 0x15, 0xf5, 0xaa, 0x3d, 0x96, 0xfb, 0x18, 0xd8, 0xb5, 0x40, 0xd8, 0xb5, 0x41, 0x14, 0xb5,
	0x5b, 0xa0, 0xa4, 0x2c, 0x17, 0x45, 0x97, 0xb5, 0xec, 0x1a, 0x2a, 0xec, 0xa2, 0x06, 0x5b, 0x78,
	0xd1, 0x45, 0x89, 0x21, 0x39, 0x22, 0x07, 0x22, 0x39, 0x04, 0x39, 0x14, 0xc0, 0x75, 0xb2, 0xc8,
	0x32, 0x9b, 0x7c, 0x46, 0xb6, 0xf9, 0x81, 0x6c, 0xb2, 0xce, 0x07, 0x24, 0xbf, 0x12, 0x70, 0x66,
	0x48, 0xca, 0xb0, 0x29, 0x28, 0xd9, 0x65, 0x23, 0x50, 0x77, 0xee, 0x3d, 0xe7, 0xcc, 0xdc, 0xcb,
	0x33, 0x04, 0x6a, 0x9c, 0x50, 0x46, 0x0d, 0x96, 0xc7, 0x38, 0x35, 0xf0, 0x82, 0xb8, 0x38, 0x72,
	0xb0, 0xce, 0x83, 0xf0, 0x5b, 0x86, 0x23, 0x17, 0x27, 0x21, 0x89, 0x98, 0x88, 0xe8, 0x3c, 0x4d,
	0xfd, 0x81, 0xf9, 0x24, 0x71, 0xad, 0x18, 0x25, 0x2c, 0x37, 0x44, 0xbd, 0x47, 0x3d, 0x5a, 0x3f,
	0x89, 0x6c, 0x75, 0x6f, 0x19, 0x9b, 0xff, 0xca, 0x85, 0x43, 0x8f, 0x52, 0x2f, 0xc0, 0xa2, 0xd6,
	0xce, 0x66, 0x06, 0x23, 0x21, 0x4e, 0x19, 0x0a, 0x63, 0x99, 0x70, 0x20, 0x2a, 0x9d, 0x24, 0x8f,
	0x19, 0x35, 0xe6, 0x38, 0xbf, 0x57, 0xaf, 0xbd, 0x56, 0xc0, 0xee, 0x65, 0x16, 0x07, 0xc4, 0x41,
	0x0c, 0xdf, 0x51, 0x86, 0xff, 0x90, 0xc2, 0xe1, 0xef, 0xe0, 0x8b, 0x38, 0xb3, 0xad, 0x39, 0xce,
	0x87, 0xca, 0x91, 0x72, 0xb2, 0x35, 0x3e, 0xd6, 0x1f, 0x6c, 0x42, 0xa0, 0xea, 0x05, 0xaa, 0x7e,
	0x9b, 0xd9, 0x01, 0x71, 0xae, 0x71, 0x6e, 0xf6, 0xe3, 0xcc, 0xbe, 0xc6, 0x39, 0x3c, 0x03, 0xfd,
	0x05, 0x65, 0xd8, 0x42, 0xc3, 0x36, 0x07, 0xd8, 0xd7, 0x1f, 0x3f, 0x05, 0xbd, 0xe0, 0x35, 0x7b,
	0x45, 0xee, 0x79, 0x55, 0x64, 0x0f, 0x3b, 0xeb, 0x16, 0x4d, 0xb4, 0xa7, 0x0a, 0x18, 0xde, 0x52,
	0x86, 0x23, 0x46, 0x50, 0x70, 0x1e, 0x46, 0x38, 0x25, 0xa8, 0xda, 0x48, 0x2d, 0x43, 0xf9, 0x14,
	0x19, 0xed, 0xf5, 0x65, 0xbc, 0x54, 0xc0, 0xe0, 0x2f, 0xea, 0xcc, 0x2b, 0xea, 0x63, 0xf0, 0x55,
	0x39, 0x08, 0x96, 0x8f, 0x89, 0xe7, 0x33, 0xae, 0xa1, 0x63, 0x7e, 0x59, 0x86, 0xa7, 0x3c, 0x0a,
	0xff, 0x04, 0xdb, 0x55, 0x62, 0xd1, 0x41, 0xc9, 0xaa, 0xea, 0xa2, 0xbd, 0x7a, 0xd9, 0x5e, 0xfd,
	0xdf, 0xb2, 0xbd, 0x93, 0x8d, 0x37, 0xef, 0x0e, 0x5b, 0xcf, 0xdf, 0x1f, 0x2a, 0xe6, 0xa0, 0x2c,
	0x2d, 0x16, 0xe1, 0x8f, 0xe0, 0xeb, 0x0a, 0x0a, 0xb9, 0x6e, 0x82, 0xd3, 0x94, 0x1f, 0xe5, 0xc0,
	0xac, 0xb4, 0x9c, 0x8b, 0xb0, 0xf6, 0x56, 0x01, 0xb0, 0xd0, 0x6b, 0xa2, 0xc8, 0xa5, 0xe1, 0x67,
	0xa2, 0x1a, 0x1e, 0x00, 0x90, 0xa0, 0xc8, 0xb5, 0xec, 0x9c, 0xe1, 0x74, 0xd8, 0xe5, 0x49, 0x9b,
	0x45, 0x64, 0x52, 0x04, 0xb4, 0x67, 0x0a, 0x50, 0x2f, 0x68, 0x34, 0x0b, 0x88, 0xc3, 0x48, 0xe4,
	0x4d, 0x31, 0x72, 0x71, 0x92, 0x56, 0x9b, 0xfb, 0x05, 0xb4, 0xfd, 0x53, 0x39, 0x09, 0xdf, 0x37,
	0x35, 0xf5, 0x1f, 0xe2, 0x45, 0xd8, 0x15, 0xa5, 0x66, 0xdb, 0x3f, 0xe5, 0x55, 0x63, 0xb9, 0xbd,
	0x75, 0xab, 0xc6, 0xda, 0x2b, 0x05, 0x0c, 0x6f, 0xb2, 0x08, 0x31, 0xe2, 0xdc, 0xa1, 0x80, 0xb8,
	0x88, 0xd1, 0xa4, 0x12, 0xf2, 0x2b, 0xe8, 0xfb, 0x3c, 0x55, 0x8a, 0xf9, 0xae, 0x09, 0x56, 0x02,
	0xca, 0x6c, 0x38, 0x02, 0xdd, 0x62, 0xda, 0xd6, 0x9a, 0x4b, 0x9e, 0x09, 0x47, 0x60, 0x87, 0x44,
	0x8b, 0x42, 0x80, 0x25, 0x30, 0xac, 0x19, 0xc1, 0x81, 0xcb, 0xcf, 0x77, 0xd3, 0x84, 0x72, 0x4d,
	0xd0, 0x5c, 0x15, 0x2b, 0xda, 0x93, 0x1e, 0xd8, 0xa8, 0x84, 0x7a, 0x60, 0xcf, 0x2d, 0x1d, 0xc2,
	0xe2, 0x2f, 0x45, 0xd9, 0x11, 0xa9, 0xfc, 0xe7, 0x26, 0x0d, 0x8f, 0x1a, 0xcb, 0xb4, 0x65, 0xee,
	0xba, 0x8f, 0x3a, 0xce, 0x02, 0xec, 0x3b, 0x75, 0xe3, 0xa4, 0xd6, 0xb4, 0x66, 0x13, 0x3b, 0x1e,
	0x37, 0xb1, 0x35, 0x37, 0x7d, 0xda, 0x32, 0x55, 0xa7, 0x79, 0x24, 0x62, 0xa0, 0x06, 0xa2, 0x4b,
	0xd6, 0xa2, 0x6c, 0x53, 0xcd, 0x2a, 0x6c, 0x68, 0xd4, 0xc4, 0xda, 0xd4, 0xdf, 0x69, 0xcb, 0x1c,
	0x06, 0x4d, 0xbd, 0x8f, 0x81, 0x1a, 0x97, 0x76, 0x65, 0x21, 0xe1, 0x57, 0x35, 0x63, 0x77, 0x35,
	0x63, 0x93, 0xd1, 0x15, 0x8c, 0x71, 0x93, 0x09, 0x5e, 0x83, 0xed, 0x90, 0x3a, 0xf3, 0x9a, 0xa4,
	0xb7, 0x7a, 0x96, 0x97, 0x6d, 0x6c, 0xda, 0x32, 0x07, 0xe1, 0xb2, 0xad, 0xfd, 0x0f, 0x76, 0x38,
	0x58, 0xc2, 0x7d, 0xa3, 0xc6, 0xec, 0x73, 0xcc, 0x9f, 0x56, 0x61, 0xde, 0xb7, 0x9a, 0x69, 0xcb,
	0x84, 0xe1, 0x83, 0xe8, 0xa4, 0x07, 0x3a, 0x69, 0x16, 0x6a, 0x33, 0x30, 0x28, 0x43, 0x97, 0x88,
	0x21, 0x38, 0x01, 0x1b, 0x4b, 0x93, 0xd7, 0x39, 0xd9, 0x1a, 0x1f, 0x35, 0x51, 0x55, 0x50, 0xdd,
	0xc2, 0x6f, 0xcc, 0xaa, 0x0e, 0x42, 0xd0, 0xf5, 0x51, 0xea, 0xf3, 0x59, 0x1a, 0x98, 0xfc, 0x59,
	0x7b, 0xa1, 0x80, 0x6f, 0x6e, 0x13, 0x4a, 0x67, 0x7f, 0xcf, 0x6e, 0xa8, 0x33, 0xbf, 0xf0, 0x51,
	0xe4, 0x61, 0xf8, 0x1b, 0xe0, 0xae, 0x9e, 0x4a, 0xaa, 0x95, 0x2f, 0x9a, 0xa4, 0x11, 0x05, 0xf0,
	0xaa, 0xbe, 0x39, 0xdb, 0x1f, 0x75, 0x73, 0x4a, 0x18, 0x79, 0x7f, 0x4e, 0x46, 0xff, 0xe9, 0x1e,
	0x61, 0x7e, 0x66, 0xeb, 0x0e, 0x0d, 0x0d, 0xd7, 0x76, 0x7c, 0x44, 0x22, 0x27, 0xa0, 0x99, 0x6b,
	0xd4, 0x78, 0xc6, 0xd2, 0x97, 0x81, 0xdd, 0xe7, 0x7f, 0xce, 0x3e, 0x04, 0x00, 0x00, 0xff, 0xff,
	0x5e, 0x65, 0x3c, 0xd6, 0x8b, 0x08, 0x00, 0x00,
}
