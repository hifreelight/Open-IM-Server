// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.1
// 	protoc        v3.21.4
// source: push/push.proto

package pbPush

import (
	sdk_ws "Open_IM/pkg/proto/sdk_ws"
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type PushMsgReq struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	OperationID  string          `protobuf:"bytes,1,opt,name=operationID,proto3" json:"operationID,omitempty"`
	MsgData      *sdk_ws.MsgData `protobuf:"bytes,2,opt,name=msgData,proto3" json:"msgData,omitempty"`
	PushToUserID string          `protobuf:"bytes,3,opt,name=pushToUserID,proto3" json:"pushToUserID,omitempty"`
}

func (x *PushMsgReq) Reset() {
	*x = PushMsgReq{}
	if protoimpl.UnsafeEnabled {
		mi := &file_push_push_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PushMsgReq) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PushMsgReq) ProtoMessage() {}

func (x *PushMsgReq) ProtoReflect() protoreflect.Message {
	mi := &file_push_push_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PushMsgReq.ProtoReflect.Descriptor instead.
func (*PushMsgReq) Descriptor() ([]byte, []int) {
	return file_push_push_proto_rawDescGZIP(), []int{0}
}

func (x *PushMsgReq) GetOperationID() string {
	if x != nil {
		return x.OperationID
	}
	return ""
}

func (x *PushMsgReq) GetMsgData() *sdk_ws.MsgData {
	if x != nil {
		return x.MsgData
	}
	return nil
}

func (x *PushMsgReq) GetPushToUserID() string {
	if x != nil {
		return x.PushToUserID
	}
	return ""
}

type PushMsgResp struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ResultCode int32 `protobuf:"varint,1,opt,name=ResultCode,proto3" json:"ResultCode,omitempty"`
}

func (x *PushMsgResp) Reset() {
	*x = PushMsgResp{}
	if protoimpl.UnsafeEnabled {
		mi := &file_push_push_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PushMsgResp) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PushMsgResp) ProtoMessage() {}

func (x *PushMsgResp) ProtoReflect() protoreflect.Message {
	mi := &file_push_push_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PushMsgResp.ProtoReflect.Descriptor instead.
func (*PushMsgResp) Descriptor() ([]byte, []int) {
	return file_push_push_proto_rawDescGZIP(), []int{1}
}

func (x *PushMsgResp) GetResultCode() int32 {
	if x != nil {
		return x.ResultCode
	}
	return 0
}

var File_push_push_proto protoreflect.FileDescriptor

var file_push_push_proto_rawDesc = []byte{
	0x0a, 0x0f, 0x70, 0x75, 0x73, 0x68, 0x2f, 0x70, 0x75, 0x73, 0x68, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x12, 0x04, 0x70, 0x75, 0x73, 0x68, 0x1a, 0x21, 0x4f, 0x70, 0x65, 0x6e, 0x5f, 0x49, 0x4d,
	0x2f, 0x70, 0x6b, 0x67, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x73, 0x64, 0x6b, 0x5f, 0x77,
	0x73, 0x2f, 0x77, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x88, 0x01, 0x0a, 0x0a, 0x50,
	0x75, 0x73, 0x68, 0x4d, 0x73, 0x67, 0x52, 0x65, 0x71, 0x12, 0x20, 0x0a, 0x0b, 0x6f, 0x70, 0x65,
	0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x49, 0x44, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b,
	0x6f, 0x70, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x49, 0x44, 0x12, 0x34, 0x0a, 0x07, 0x6d,
	0x73, 0x67, 0x44, 0x61, 0x74, 0x61, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x73,
	0x65, 0x72, 0x76, 0x65, 0x72, 0x5f, 0x61, 0x70, 0x69, 0x5f, 0x70, 0x61, 0x72, 0x61, 0x6d, 0x73,
	0x2e, 0x4d, 0x73, 0x67, 0x44, 0x61, 0x74, 0x61, 0x52, 0x07, 0x6d, 0x73, 0x67, 0x44, 0x61, 0x74,
	0x61, 0x12, 0x22, 0x0a, 0x0c, 0x70, 0x75, 0x73, 0x68, 0x54, 0x6f, 0x55, 0x73, 0x65, 0x72, 0x49,
	0x44, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0c, 0x70, 0x75, 0x73, 0x68, 0x54, 0x6f, 0x55,
	0x73, 0x65, 0x72, 0x49, 0x44, 0x22, 0x2d, 0x0a, 0x0b, 0x50, 0x75, 0x73, 0x68, 0x4d, 0x73, 0x67,
	0x52, 0x65, 0x73, 0x70, 0x12, 0x1e, 0x0a, 0x0a, 0x52, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x43, 0x6f,
	0x64, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x05, 0x52, 0x0a, 0x52, 0x65, 0x73, 0x75, 0x6c, 0x74,
	0x43, 0x6f, 0x64, 0x65, 0x32, 0x40, 0x0a, 0x0e, 0x50, 0x75, 0x73, 0x68, 0x4d, 0x73, 0x67, 0x53,
	0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x2e, 0x0a, 0x07, 0x50, 0x75, 0x73, 0x68, 0x4d, 0x73,
	0x67, 0x12, 0x10, 0x2e, 0x70, 0x75, 0x73, 0x68, 0x2e, 0x50, 0x75, 0x73, 0x68, 0x4d, 0x73, 0x67,
	0x52, 0x65, 0x71, 0x1a, 0x11, 0x2e, 0x70, 0x75, 0x73, 0x68, 0x2e, 0x50, 0x75, 0x73, 0x68, 0x4d,
	0x73, 0x67, 0x52, 0x65, 0x73, 0x70, 0x42, 0x0f, 0x5a, 0x0d, 0x2e, 0x2f, 0x70, 0x75, 0x73, 0x68,
	0x3b, 0x70, 0x62, 0x50, 0x75, 0x73, 0x68, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_push_push_proto_rawDescOnce sync.Once
	file_push_push_proto_rawDescData = file_push_push_proto_rawDesc
)

func file_push_push_proto_rawDescGZIP() []byte {
	file_push_push_proto_rawDescOnce.Do(func() {
		file_push_push_proto_rawDescData = protoimpl.X.CompressGZIP(file_push_push_proto_rawDescData)
	})
	return file_push_push_proto_rawDescData
}

var file_push_push_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_push_push_proto_goTypes = []interface{}{
	(*PushMsgReq)(nil),     // 0: push.PushMsgReq
	(*PushMsgResp)(nil),    // 1: push.PushMsgResp
	(*sdk_ws.MsgData)(nil), // 2: server_api_params.MsgData
}
var file_push_push_proto_depIdxs = []int32{
	2, // 0: push.PushMsgReq.msgData:type_name -> server_api_params.MsgData
	0, // 1: push.PushMsgService.PushMsg:input_type -> push.PushMsgReq
	1, // 2: push.PushMsgService.PushMsg:output_type -> push.PushMsgResp
	2, // [2:3] is the sub-list for method output_type
	1, // [1:2] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_push_push_proto_init() }
func file_push_push_proto_init() {
	if File_push_push_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_push_push_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PushMsgReq); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_push_push_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PushMsgResp); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_push_push_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_push_push_proto_goTypes,
		DependencyIndexes: file_push_push_proto_depIdxs,
		MessageInfos:      file_push_push_proto_msgTypes,
	}.Build()
	File_push_push_proto = out.File
	file_push_push_proto_rawDesc = nil
	file_push_push_proto_goTypes = nil
	file_push_push_proto_depIdxs = nil
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConnInterface

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion6

// PushMsgServiceClient is the client API for PushMsgService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type PushMsgServiceClient interface {
	PushMsg(ctx context.Context, in *PushMsgReq, opts ...grpc.CallOption) (*PushMsgResp, error)
}

type pushMsgServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewPushMsgServiceClient(cc grpc.ClientConnInterface) PushMsgServiceClient {
	return &pushMsgServiceClient{cc}
}

func (c *pushMsgServiceClient) PushMsg(ctx context.Context, in *PushMsgReq, opts ...grpc.CallOption) (*PushMsgResp, error) {
	out := new(PushMsgResp)
	err := c.cc.Invoke(ctx, "/push.PushMsgService/PushMsg", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// PushMsgServiceServer is the server API for PushMsgService service.
type PushMsgServiceServer interface {
	PushMsg(context.Context, *PushMsgReq) (*PushMsgResp, error)
}

// UnimplementedPushMsgServiceServer can be embedded to have forward compatible implementations.
type UnimplementedPushMsgServiceServer struct {
}

func (*UnimplementedPushMsgServiceServer) PushMsg(context.Context, *PushMsgReq) (*PushMsgResp, error) {
	return nil, status.Errorf(codes.Unimplemented, "method PushMsg not implemented")
}

func RegisterPushMsgServiceServer(s *grpc.Server, srv PushMsgServiceServer) {
	s.RegisterService(&_PushMsgService_serviceDesc, srv)
}

func _PushMsgService_PushMsg_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(PushMsgReq)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PushMsgServiceServer).PushMsg(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/push.PushMsgService/PushMsg",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PushMsgServiceServer).PushMsg(ctx, req.(*PushMsgReq))
	}
	return interceptor(ctx, in, info, handler)
}

var _PushMsgService_serviceDesc = grpc.ServiceDesc{
	ServiceName: "push.PushMsgService",
	HandlerType: (*PushMsgServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "PushMsg",
			Handler:    _PushMsgService_PushMsg_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "push/push.proto",
}
