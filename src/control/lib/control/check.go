//
// (C) Copyright 2022 Intel Corporation.
//
// SPDX-License-Identifier: BSD-2-Clause-Patent
//

package control

import (
	"context"
	"encoding/json"

	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"

	chkpb "github.com/daos-stack/daos/src/control/common/proto/chk"
	mgmtpb "github.com/daos-stack/daos/src/control/common/proto/mgmt"
)

type SystemCheckEnableReq struct {
	unaryRequest
	msRequest

	mgmtpb.CheckEnableReq
}

// SystemCheckEnable enables the system checker.
func SystemCheckEnable(ctx context.Context, rpcClient UnaryInvoker, req *SystemCheckEnableReq) error {
	if req == nil {
		return errors.Errorf("nil %T", req)
	}

	req.CheckEnableReq.Sys = req.getSystem(rpcClient)
	req.setRPC(func(ctx context.Context, conn *grpc.ClientConn) (proto.Message, error) {
		return mgmtpb.NewMgmtSvcClient(conn).SystemCheckEnable(ctx, &req.CheckEnableReq)
	})
	rpcClient.Debugf("DAOS system checker enable request: %+v", req)

	ur, err := rpcClient.InvokeUnaryRPC(ctx, req)
	if err != nil {
		return err
	}
	ms, err := ur.getMSResponse()
	if err != nil {
		return err
	}
	rpcClient.Debugf("DAOS system checker enable response: %+v", ms)

	return nil
}

type SystemCheckDisableReq struct {
	unaryRequest
	msRequest

	mgmtpb.CheckDisableReq
}

// SystemCheckDisable disables the system checker.
func SystemCheckDisable(ctx context.Context, rpcClient UnaryInvoker, req *SystemCheckDisableReq) error {
	if req == nil {
		return errors.Errorf("nil %T", req)
	}

	req.CheckDisableReq.Sys = req.getSystem(rpcClient)
	req.setRPC(func(ctx context.Context, conn *grpc.ClientConn) (proto.Message, error) {
		return mgmtpb.NewMgmtSvcClient(conn).SystemCheckDisable(ctx, &req.CheckDisableReq)
	})
	rpcClient.Debugf("DAOS system checker disable request: %+v", req)

	ur, err := rpcClient.InvokeUnaryRPC(ctx, req)
	if err != nil {
		return err
	}
	ms, err := ur.getMSResponse()
	if err != nil {
		return err
	}
	rpcClient.Debugf("DAOS system checker disable response: %+v", ms)

	return nil
}

const (
	SystemCheckFlagDryRun  = uint32(chkpb.CheckFlag_CF_DRYRUN)
	SystemCheckFlagReset   = uint32(chkpb.CheckFlag_CF_RESET)
	SystemCheckFlagFailout = uint32(chkpb.CheckFlag_CF_FAILOUT)
	SystemCheckFlagAuto    = uint32(chkpb.CheckFlag_CF_AUTO)
)

type CheckPolicy struct {
	mgmtpb.CheckInconsistPolicy
}

func (p *CheckPolicy) Set(class, action string) error {
	if cls, ok := chkpb.CheckInconsistClass_value[class]; ok {
		p.InconsistCas = chkpb.CheckInconsistClass(cls)
	} else {
		return errors.Errorf("invalid policy class %q", class)
	}
	if act, ok := chkpb.CheckInconsistAction_value[action]; ok {
		p.InconsistAct = chkpb.CheckInconsistAction(act)
	} else {
		return errors.Errorf("invalid policy action %q", action)
	}

	return nil
}

func CheckerPolicyClasses() []string {
	names := make([]string, 0, len(chkpb.CheckInconsistClass_value))
	for name := range chkpb.CheckInconsistClass_value {
		names = append(names, name)
	}
	return names
}

func CheckerPolicyActions() []string {
	names := make([]string, 0, len(chkpb.CheckInconsistAction_value))
	for name := range chkpb.CheckInconsistAction_value {
		names = append(names, name)
	}
	return names
}

type SystemCheckStartReq struct {
	unaryRequest
	msRequest

	Policies []*CheckPolicy
	mgmtpb.CheckStartReq
}

// SystemCheckStart starts the system checker.
func SystemCheckStart(ctx context.Context, rpcClient UnaryInvoker, req *SystemCheckStartReq) error {
	if req == nil {
		return errors.Errorf("nil %T", req)
	}

	req.CheckStartReq.Sys = req.getSystem(rpcClient)
	for _, p := range req.Policies {
		req.CheckStartReq.Policies = append(req.CheckStartReq.Policies, &p.CheckInconsistPolicy)
	}
	req.setRPC(func(ctx context.Context, conn *grpc.ClientConn) (proto.Message, error) {
		return mgmtpb.NewMgmtSvcClient(conn).SystemCheckStart(ctx, &req.CheckStartReq)
	})
	rpcClient.Debugf("DAOS system check start request: %+v", req)

	ur, err := rpcClient.InvokeUnaryRPC(ctx, req)
	if err != nil {
		return err
	}
	ms, err := ur.getMSResponse()
	if err != nil {
		return err
	}
	rpcClient.Debugf("DAOS system check start response: %+v", ms)

	return nil
}

type SystemCheckStopReq struct {
	unaryRequest
	msRequest

	mgmtpb.CheckStopReq
}

// SystemCheckStop stops the system checker.
func SystemCheckStop(ctx context.Context, rpcClient UnaryInvoker, req *SystemCheckStopReq) error {
	if req == nil {
		return errors.Errorf("nil %T", req)
	}

	req.CheckStopReq.Sys = req.getSystem(rpcClient)
	req.setRPC(func(ctx context.Context, conn *grpc.ClientConn) (proto.Message, error) {
		return mgmtpb.NewMgmtSvcClient(conn).SystemCheckStop(ctx, &req.CheckStopReq)
	})
	rpcClient.Debugf("DAOS system check stop request: %+v", req)

	ur, err := rpcClient.InvokeUnaryRPC(ctx, req)
	if err != nil {
		return err
	}
	ms, err := ur.getMSResponse()
	if err != nil {
		return err
	}
	rpcClient.Debugf("DAOS system check stop response: %+v", ms)

	return nil
}

type SystemCheckQueryReq struct {
	unaryRequest
	msRequest

	mgmtpb.CheckQueryReq
}

type SystemCheckQueryResp struct {
	mgmtpb.CheckQueryResp
}

// SystemCheckQuery queries the system checker status.
func SystemCheckQuery(ctx context.Context, rpcClient UnaryInvoker, req *SystemCheckQueryReq) (*SystemCheckQueryResp, error) {
	if req == nil {
		return nil, errors.Errorf("nil %T", req)
	}

	req.CheckQueryReq.Sys = req.getSystem(rpcClient)
	req.setRPC(func(ctx context.Context, conn *grpc.ClientConn) (proto.Message, error) {
		return mgmtpb.NewMgmtSvcClient(conn).SystemCheckQuery(ctx, &req.CheckQueryReq)
	})
	rpcClient.Debugf("DAOS system check query request: %+v", req)

	ur, err := rpcClient.InvokeUnaryRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	ms, err := ur.getMSResponse()
	if err != nil {
		return nil, err
	}
	rpcClient.Debugf("DAOS system check query response: %+v", ms)

	resp := new(SystemCheckQueryResp)
	if pbResp, ok := ms.(*mgmtpb.CheckQueryResp); ok {
		resp.CheckQueryResp = *pbResp
	} else {
		return nil, errors.Errorf("unexpected response type %T", ms)
	}
	return resp, nil
}

type SystemCheckPropReq struct {
	unaryRequest
	msRequest

	mgmtpb.CheckPropReq
}

type SystemCheckPropResp struct {
	pb *mgmtpb.CheckPropResp
}

func (r *SystemCheckPropResp) MarshalJSON() ([]byte, error) {
	return json.Marshal(r.pb)
}

// SystemCheckProp queries the system checker properties.
func SystemCheckProp(ctx context.Context, rpcClient UnaryInvoker, req *SystemCheckPropReq) (*SystemCheckPropResp, error) {
	if req == nil {
		return nil, errors.Errorf("nil %T", req)
	}

	req.CheckPropReq.Sys = req.getSystem(rpcClient)
	req.setRPC(func(ctx context.Context, conn *grpc.ClientConn) (proto.Message, error) {
		return mgmtpb.NewMgmtSvcClient(conn).SystemCheckProp(ctx, &req.CheckPropReq)
	})
	rpcClient.Debugf("DAOS system check prop request: %+v", req)

	ur, err := rpcClient.InvokeUnaryRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	ms, err := ur.getMSResponse()
	if err != nil {
		return nil, err
	}
	rpcClient.Debugf("DAOS system check prop response: %+v", ms)

	resp := new(SystemCheckPropResp)
	if pbResp, ok := ms.(*mgmtpb.CheckPropResp); ok {
		resp.pb = pbResp
	} else {
		return nil, errors.Errorf("unexpected response type %T", ms)
	}
	return resp, nil
}

type SystemCheckRepairReq struct {
	unaryRequest
	msRequest

	mgmtpb.CheckActReq
}

func (r *SystemCheckRepairReq) SetAction(action int32) error {
	if _, ok := chkpb.CheckInconsistAction_name[action]; !ok {
		return errors.Errorf("invalid action %d", action)
	}
	r.Act = chkpb.CheckInconsistAction(action)
	return nil
}

// SystemCheckRepair sends a request to the system checker to indicate
// what the desired repair action is for a reported inconsistency.
func SystemCheckRepair(ctx context.Context, rpcClient UnaryInvoker, req *SystemCheckRepairReq) error {
	if req == nil {
		return errors.Errorf("nil %T", req)
	}

	req.setRPC(func(ctx context.Context, conn *grpc.ClientConn) (proto.Message, error) {
		req.CheckActReq.Sys = req.getSystem(rpcClient)
		return mgmtpb.NewMgmtSvcClient(conn).SystemCheckRepair(ctx, &req.CheckActReq)
	})
	rpcClient.Debugf("DAOS system check repair request: %+v", req)

	ur, err := rpcClient.InvokeUnaryRPC(ctx, req)
	if err != nil {
		return err
	}
	msResp, err := ur.getMSResponse()
	if err != nil {
		return err
	}
	rpcClient.Debugf("DAOS system check repair response: %+v", msResp)

	return nil
}
