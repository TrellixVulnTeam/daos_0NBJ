/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: check.proto */

#ifndef PROTOBUF_C_check_2eproto__INCLUDED
#define PROTOBUF_C_check_2eproto__INCLUDED

#include <protobuf-c/protobuf-c.h>

PROTOBUF_C__BEGIN_DECLS

#if PROTOBUF_C_VERSION_NUMBER < 1003000
# error This file was generated by a newer version of protoc-c which is incompatible with your libprotobuf-c headers. Please update your headers.
#elif 1004000 < PROTOBUF_C_MIN_COMPILER_VERSION
# error This file was generated by an older version of protoc-c which is incompatible with your libprotobuf-c headers. Please regenerate this file with a newer version of protoc-c.
#endif


typedef struct Mgmt__CheckInconsistPolicy Mgmt__CheckInconsistPolicy;
typedef struct Mgmt__CheckStartReq Mgmt__CheckStartReq;
typedef struct Mgmt__CheckStartResp Mgmt__CheckStartResp;
typedef struct Mgmt__CheckStopReq Mgmt__CheckStopReq;
typedef struct Mgmt__CheckStopResp Mgmt__CheckStopResp;
typedef struct Mgmt__CheckQueryReq Mgmt__CheckQueryReq;
typedef struct Mgmt__CheckQueryTime Mgmt__CheckQueryTime;
typedef struct Mgmt__CheckQueryInconsist Mgmt__CheckQueryInconsist;
typedef struct Mgmt__CheckQueryTarget Mgmt__CheckQueryTarget;
typedef struct Mgmt__CheckQueryPool Mgmt__CheckQueryPool;
typedef struct Mgmt__CheckQueryResp Mgmt__CheckQueryResp;
typedef struct Mgmt__CheckPropReq Mgmt__CheckPropReq;
typedef struct Mgmt__CheckPropResp Mgmt__CheckPropResp;
typedef struct Mgmt__CheckActReq Mgmt__CheckActReq;
typedef struct Mgmt__CheckActResp Mgmt__CheckActResp;


/* --- enums --- */


/* --- messages --- */

/*
 * The pairs for kinds of inconsistency and related repair action. The control plane need to
 * generate such policy array from some configuration file either via command line option or
 * some default location, such as /etc/daos/daos_check.yml. Such policy arrge will be passed
 * to DAOS engine when start check and cannot changed during check scanning, but can be list
 * via 'dmg check prop' - see CheckPropResp.
 */
struct  Mgmt__CheckInconsistPolicy
{
  ProtobufCMessage base;
  /*
   * See CheckInconsistClass.
   */
  uint32_t inconsist_cas;
  /*
   * See CheckInconsistAction.
   */
  uint32_t inconsist_act;
};
#define MGMT__CHECK_INCONSIST_POLICY__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&mgmt__check_inconsist_policy__descriptor) \
    , 0, 0 }


/*
 * For 'dmg check start'.
 */
struct  Mgmt__CheckStartReq
{
  ProtobufCMessage base;
  /*
   * DAOS system identifier.
   */
  char *sys;
  /*
   * See CheckFlag.
   */
  uint32_t flags;
  /*
   * The list of ranks to start DAOS check. Cannot be empty.
   * The control plane will generate the ranks list and guarantee that any rank in the system
   * is either will participate in check or has been excluded. Otherwise, partial ranks check
   * may cause some unexpected and unrecoverable result unless the specified pool(s) does not
   * exist on those missed rank(s).
   */
  size_t n_ranks;
  uint32_t *ranks;
  /*
   * UUID for the pools for which to start DAOS check.
   * If empty, then start DAOS check for all pools in the system.
   */
  size_t n_uuids;
  char **uuids;
  /*
   * Policy array for handling inconsistency.
   */
  size_t n_policies;
  Mgmt__CheckInconsistPolicy **policies;
};
#define MGMT__CHECK_START_REQ__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&mgmt__check_start_req__descriptor) \
    , (char *)protobuf_c_empty_string, 0, 0,NULL, 0,NULL, 0,NULL }


/*
 * CheckStartResp returns the result of check start.
 */
struct  Mgmt__CheckStartResp
{
  ProtobufCMessage base;
  /*
   * DAOS error code.
   */
  int32_t status;
};
#define MGMT__CHECK_START_RESP__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&mgmt__check_start_resp__descriptor) \
    , 0 }


/*
 * For 'dmg check stop'.
 */
struct  Mgmt__CheckStopReq
{
  ProtobufCMessage base;
  /*
   * DAOS system identifier.
   */
  char *sys;
  /*
   * UUID for the pools for which to stop DAOS check.
   * If empty, then stop check for all pools in the system.
   */
  size_t n_uuids;
  char **uuids;
};
#define MGMT__CHECK_STOP_REQ__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&mgmt__check_stop_req__descriptor) \
    , (char *)protobuf_c_empty_string, 0,NULL }


/*
 * CheckStopResp returns the result of check stop.
 */
struct  Mgmt__CheckStopResp
{
  ProtobufCMessage base;
  /*
   * DAOS error code.
   */
  int32_t status;
};
#define MGMT__CHECK_STOP_RESP__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&mgmt__check_stop_resp__descriptor) \
    , 0 }


/*
 * For 'dmg check query'.
 */
struct  Mgmt__CheckQueryReq
{
  ProtobufCMessage base;
  /*
   * DAOS system identifier.
   */
  char *sys;
  /*
   * UUID for the pools for which to query DAOS check.
   * If empty, then query DAOS check for all pools in the system.
   */
  size_t n_uuids;
  char **uuids;
};
#define MGMT__CHECK_QUERY_REQ__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&mgmt__check_query_req__descriptor) \
    , (char *)protobuf_c_empty_string, 0,NULL }


/*
 * Time information on related component: system, pool or target.
 */
struct  Mgmt__CheckQueryTime
{
  ProtobufCMessage base;
  /*
   * The time of check instance being started on the component.
   */
  uint64_t start_time;
  /*
   * If the check instance is still running on the component, then it is the estimated
   * remaining time to complete the check on the component. Otherwise, it is the time
   * of the check instance completed, failed or stopped on the component.
   */
  uint64_t misc_time;
};
#define MGMT__CHECK_QUERY_TIME__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&mgmt__check_query_time__descriptor) \
    , 0, 0 }


/*
 * Inconsistency statistics on related component: system, pool or target.
 */
struct  Mgmt__CheckQueryInconsist
{
  ProtobufCMessage base;
  /*
   * The count of total found inconsistency on the component.
   */
  uint32_t total;
  /*
   * The count of repaired inconsistency on the component.
   */
  uint32_t repaired;
  /*
   * The count of ignored inconsistency on the component.
   */
  uint32_t ignored;
  /*
   * The count of fail to repaired inconsistency on the component.
   */
  uint32_t failed;
};
#define MGMT__CHECK_QUERY_INCONSIST__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&mgmt__check_query_inconsist__descriptor) \
    , 0, 0, 0, 0 }


/*
 * Check query result for the pool shard on the target.
 */
struct  Mgmt__CheckQueryTarget
{
  ProtobufCMessage base;
  /*
   * Rank ID.
   */
  uint32_t rank;
  /*
   * Target index in the rank.
   */
  uint32_t target;
  /*
   * Check instance status on this target - see CheckInstStatus.
   */
  uint32_t status;
  /*
   * Inconsistency statistics during the phases range
   * [CSP_DTX_RESYNC, OSP_AGGREGATION] for the pool shard on the target.
   */
  Mgmt__CheckQueryInconsist *inconsistency;
  /*
   * Time information for the pool shard on the target if applicable.
   */
  Mgmt__CheckQueryTime *time;
};
#define MGMT__CHECK_QUERY_TARGET__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&mgmt__check_query_target__descriptor) \
    , 0, 0, 0, NULL, NULL }


/*
 * Check query result for the pool.
 */
struct  Mgmt__CheckQueryPool
{
  ProtobufCMessage base;
  /*
   * Pool UUID.
   */
  char *uuid;
  /*
   * Pool status - see CheckPoolStatus.
   */
  uint32_t status;
  /*
   * Scan phase - see CheckScanPhase.
   */
  uint32_t phase;
  /*
   * Inconsistency statistics during the phases range
   * [CSP_POOL_MBS, CSP_CONT_CLEANUP] for the pool.
   */
  Mgmt__CheckQueryInconsist *inconsistency;
  /*
   * Time information for the pool if applicable.
   */
  Mgmt__CheckQueryTime *time;
  /*
   * Per target based query result for the phases since CSP_DTX_RESYNC.
   */
  size_t n_targets;
  Mgmt__CheckQueryTarget **targets;
};
#define MGMT__CHECK_QUERY_POOL__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&mgmt__check_query_pool__descriptor) \
    , (char *)protobuf_c_empty_string, 0, 0, NULL, NULL, 0,NULL }


/*
 * CheckQueryResp returns DAOS check status for required pool(s) or the whole system.
 * Depend on the dmg command line option, the control plane needs to reorganize the query
 * results with summary (of pool shards from targets) and different detailed information.
 */
struct  Mgmt__CheckQueryResp
{
  ProtobufCMessage base;
  /*
   * DAOS error code.
   */
  int32_t req_status;
  /*
   * The whole check instance status depends on the each engine status:
   * As long as one target is in CIS_RUNNING, then the instance is CIS_RUNNING.
   * Otherwise, in turn with the status of CIS_FAILED, CIS_CRASHED, CIS_PAUSED,
   * CIS_STOPPED, CIS_COMPLETED.
   */
  uint32_t ins_status;
  /*
   * Scan phase - see CheckScanPhase. Before moving to CSP_POOL_MBS, the check
   * instance status is maintained on the check leader. And then multiple pools
   * can be processed in parallel, so the instance phase for different pools may
   * be different, see CheckQueryPool::phase.
   */
  uint32_t ins_phase;
  /*
   * Inconsistency statistics during the phases range
   * [CSP_PREPARE, CSP_POOL_LIST] for the whole system.
   */
  Mgmt__CheckQueryInconsist *inconsistency;
  /*
   * Time information for the whole system if applicable.
   */
  Mgmt__CheckQueryTime *time;
  /*
   * Per pool based query result for the phases since CSP_POOL_MBS.
   */
  size_t n_pools;
  Mgmt__CheckQueryPool **pools;
};
#define MGMT__CHECK_QUERY_RESP__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&mgmt__check_query_resp__descriptor) \
    , 0, 0, 0, NULL, NULL, 0,NULL }


/*
 * For 'dmg check prop'
 */
struct  Mgmt__CheckPropReq
{
  ProtobufCMessage base;
  /*
   * DAOS system identifier.
   */
  char *sys;
};
#define MGMT__CHECK_PROP_REQ__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&mgmt__check_prop_req__descriptor) \
    , (char *)protobuf_c_empty_string }


/*
 * CheckPropResp returns the result of check prop and the properties when start check.
 */
struct  Mgmt__CheckPropResp
{
  ProtobufCMessage base;
  /*
   * DAOS error code.
   */
  int32_t status;
  /*
   * The flags when start check - see CheckFlag.
   */
  uint32_t flags;
  /*
   * Inconsistency policy array.
   */
  size_t n_policies;
  Mgmt__CheckInconsistPolicy **policies;
};
#define MGMT__CHECK_PROP_RESP__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&mgmt__check_prop_resp__descriptor) \
    , 0, 0, 0,NULL }


/*
 * For the admin's decision from DAOS check interaction.
 */
struct  Mgmt__CheckActReq
{
  ProtobufCMessage base;
  /*
   * DAOS system identifier.
   */
  char *sys;
  /*
   * DAOS RAS event sequence - see RASEvent::extended_info::check_info::chk_inconsist_seq.
   */
  uint64_t seq;
  /*
   * The decision from RASEvent::extended_info::check_info::chk_opts.
   */
  uint32_t act;
  /*
   * The same action is applicable to the same type of inconsistency.
   */
  protobuf_c_boolean for_all;
};
#define MGMT__CHECK_ACT_REQ__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&mgmt__check_act_req__descriptor) \
    , (char *)protobuf_c_empty_string, 0, 0, 0 }


/*
 * CheckActResp returns the result of executing admin's decision.
 */
struct  Mgmt__CheckActResp
{
  ProtobufCMessage base;
  /*
   * DAOS error code.
   */
  int32_t status;
};
#define MGMT__CHECK_ACT_RESP__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&mgmt__check_act_resp__descriptor) \
    , 0 }


/* Mgmt__CheckInconsistPolicy methods */
void   mgmt__check_inconsist_policy__init
                     (Mgmt__CheckInconsistPolicy         *message);
size_t mgmt__check_inconsist_policy__get_packed_size
                     (const Mgmt__CheckInconsistPolicy   *message);
size_t mgmt__check_inconsist_policy__pack
                     (const Mgmt__CheckInconsistPolicy   *message,
                      uint8_t             *out);
size_t mgmt__check_inconsist_policy__pack_to_buffer
                     (const Mgmt__CheckInconsistPolicy   *message,
                      ProtobufCBuffer     *buffer);
Mgmt__CheckInconsistPolicy *
       mgmt__check_inconsist_policy__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   mgmt__check_inconsist_policy__free_unpacked
                     (Mgmt__CheckInconsistPolicy *message,
                      ProtobufCAllocator *allocator);
/* Mgmt__CheckStartReq methods */
void   mgmt__check_start_req__init
                     (Mgmt__CheckStartReq         *message);
size_t mgmt__check_start_req__get_packed_size
                     (const Mgmt__CheckStartReq   *message);
size_t mgmt__check_start_req__pack
                     (const Mgmt__CheckStartReq   *message,
                      uint8_t             *out);
size_t mgmt__check_start_req__pack_to_buffer
                     (const Mgmt__CheckStartReq   *message,
                      ProtobufCBuffer     *buffer);
Mgmt__CheckStartReq *
       mgmt__check_start_req__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   mgmt__check_start_req__free_unpacked
                     (Mgmt__CheckStartReq *message,
                      ProtobufCAllocator *allocator);
/* Mgmt__CheckStartResp methods */
void   mgmt__check_start_resp__init
                     (Mgmt__CheckStartResp         *message);
size_t mgmt__check_start_resp__get_packed_size
                     (const Mgmt__CheckStartResp   *message);
size_t mgmt__check_start_resp__pack
                     (const Mgmt__CheckStartResp   *message,
                      uint8_t             *out);
size_t mgmt__check_start_resp__pack_to_buffer
                     (const Mgmt__CheckStartResp   *message,
                      ProtobufCBuffer     *buffer);
Mgmt__CheckStartResp *
       mgmt__check_start_resp__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   mgmt__check_start_resp__free_unpacked
                     (Mgmt__CheckStartResp *message,
                      ProtobufCAllocator *allocator);
/* Mgmt__CheckStopReq methods */
void   mgmt__check_stop_req__init
                     (Mgmt__CheckStopReq         *message);
size_t mgmt__check_stop_req__get_packed_size
                     (const Mgmt__CheckStopReq   *message);
size_t mgmt__check_stop_req__pack
                     (const Mgmt__CheckStopReq   *message,
                      uint8_t             *out);
size_t mgmt__check_stop_req__pack_to_buffer
                     (const Mgmt__CheckStopReq   *message,
                      ProtobufCBuffer     *buffer);
Mgmt__CheckStopReq *
       mgmt__check_stop_req__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   mgmt__check_stop_req__free_unpacked
                     (Mgmt__CheckStopReq *message,
                      ProtobufCAllocator *allocator);
/* Mgmt__CheckStopResp methods */
void   mgmt__check_stop_resp__init
                     (Mgmt__CheckStopResp         *message);
size_t mgmt__check_stop_resp__get_packed_size
                     (const Mgmt__CheckStopResp   *message);
size_t mgmt__check_stop_resp__pack
                     (const Mgmt__CheckStopResp   *message,
                      uint8_t             *out);
size_t mgmt__check_stop_resp__pack_to_buffer
                     (const Mgmt__CheckStopResp   *message,
                      ProtobufCBuffer     *buffer);
Mgmt__CheckStopResp *
       mgmt__check_stop_resp__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   mgmt__check_stop_resp__free_unpacked
                     (Mgmt__CheckStopResp *message,
                      ProtobufCAllocator *allocator);
/* Mgmt__CheckQueryReq methods */
void   mgmt__check_query_req__init
                     (Mgmt__CheckQueryReq         *message);
size_t mgmt__check_query_req__get_packed_size
                     (const Mgmt__CheckQueryReq   *message);
size_t mgmt__check_query_req__pack
                     (const Mgmt__CheckQueryReq   *message,
                      uint8_t             *out);
size_t mgmt__check_query_req__pack_to_buffer
                     (const Mgmt__CheckQueryReq   *message,
                      ProtobufCBuffer     *buffer);
Mgmt__CheckQueryReq *
       mgmt__check_query_req__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   mgmt__check_query_req__free_unpacked
                     (Mgmt__CheckQueryReq *message,
                      ProtobufCAllocator *allocator);
/* Mgmt__CheckQueryTime methods */
void   mgmt__check_query_time__init
                     (Mgmt__CheckQueryTime         *message);
size_t mgmt__check_query_time__get_packed_size
                     (const Mgmt__CheckQueryTime   *message);
size_t mgmt__check_query_time__pack
                     (const Mgmt__CheckQueryTime   *message,
                      uint8_t             *out);
size_t mgmt__check_query_time__pack_to_buffer
                     (const Mgmt__CheckQueryTime   *message,
                      ProtobufCBuffer     *buffer);
Mgmt__CheckQueryTime *
       mgmt__check_query_time__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   mgmt__check_query_time__free_unpacked
                     (Mgmt__CheckQueryTime *message,
                      ProtobufCAllocator *allocator);
/* Mgmt__CheckQueryInconsist methods */
void   mgmt__check_query_inconsist__init
                     (Mgmt__CheckQueryInconsist         *message);
size_t mgmt__check_query_inconsist__get_packed_size
                     (const Mgmt__CheckQueryInconsist   *message);
size_t mgmt__check_query_inconsist__pack
                     (const Mgmt__CheckQueryInconsist   *message,
                      uint8_t             *out);
size_t mgmt__check_query_inconsist__pack_to_buffer
                     (const Mgmt__CheckQueryInconsist   *message,
                      ProtobufCBuffer     *buffer);
Mgmt__CheckQueryInconsist *
       mgmt__check_query_inconsist__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   mgmt__check_query_inconsist__free_unpacked
                     (Mgmt__CheckQueryInconsist *message,
                      ProtobufCAllocator *allocator);
/* Mgmt__CheckQueryTarget methods */
void   mgmt__check_query_target__init
                     (Mgmt__CheckQueryTarget         *message);
size_t mgmt__check_query_target__get_packed_size
                     (const Mgmt__CheckQueryTarget   *message);
size_t mgmt__check_query_target__pack
                     (const Mgmt__CheckQueryTarget   *message,
                      uint8_t             *out);
size_t mgmt__check_query_target__pack_to_buffer
                     (const Mgmt__CheckQueryTarget   *message,
                      ProtobufCBuffer     *buffer);
Mgmt__CheckQueryTarget *
       mgmt__check_query_target__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   mgmt__check_query_target__free_unpacked
                     (Mgmt__CheckQueryTarget *message,
                      ProtobufCAllocator *allocator);
/* Mgmt__CheckQueryPool methods */
void   mgmt__check_query_pool__init
                     (Mgmt__CheckQueryPool         *message);
size_t mgmt__check_query_pool__get_packed_size
                     (const Mgmt__CheckQueryPool   *message);
size_t mgmt__check_query_pool__pack
                     (const Mgmt__CheckQueryPool   *message,
                      uint8_t             *out);
size_t mgmt__check_query_pool__pack_to_buffer
                     (const Mgmt__CheckQueryPool   *message,
                      ProtobufCBuffer     *buffer);
Mgmt__CheckQueryPool *
       mgmt__check_query_pool__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   mgmt__check_query_pool__free_unpacked
                     (Mgmt__CheckQueryPool *message,
                      ProtobufCAllocator *allocator);
/* Mgmt__CheckQueryResp methods */
void   mgmt__check_query_resp__init
                     (Mgmt__CheckQueryResp         *message);
size_t mgmt__check_query_resp__get_packed_size
                     (const Mgmt__CheckQueryResp   *message);
size_t mgmt__check_query_resp__pack
                     (const Mgmt__CheckQueryResp   *message,
                      uint8_t             *out);
size_t mgmt__check_query_resp__pack_to_buffer
                     (const Mgmt__CheckQueryResp   *message,
                      ProtobufCBuffer     *buffer);
Mgmt__CheckQueryResp *
       mgmt__check_query_resp__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   mgmt__check_query_resp__free_unpacked
                     (Mgmt__CheckQueryResp *message,
                      ProtobufCAllocator *allocator);
/* Mgmt__CheckPropReq methods */
void   mgmt__check_prop_req__init
                     (Mgmt__CheckPropReq         *message);
size_t mgmt__check_prop_req__get_packed_size
                     (const Mgmt__CheckPropReq   *message);
size_t mgmt__check_prop_req__pack
                     (const Mgmt__CheckPropReq   *message,
                      uint8_t             *out);
size_t mgmt__check_prop_req__pack_to_buffer
                     (const Mgmt__CheckPropReq   *message,
                      ProtobufCBuffer     *buffer);
Mgmt__CheckPropReq *
       mgmt__check_prop_req__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   mgmt__check_prop_req__free_unpacked
                     (Mgmt__CheckPropReq *message,
                      ProtobufCAllocator *allocator);
/* Mgmt__CheckPropResp methods */
void   mgmt__check_prop_resp__init
                     (Mgmt__CheckPropResp         *message);
size_t mgmt__check_prop_resp__get_packed_size
                     (const Mgmt__CheckPropResp   *message);
size_t mgmt__check_prop_resp__pack
                     (const Mgmt__CheckPropResp   *message,
                      uint8_t             *out);
size_t mgmt__check_prop_resp__pack_to_buffer
                     (const Mgmt__CheckPropResp   *message,
                      ProtobufCBuffer     *buffer);
Mgmt__CheckPropResp *
       mgmt__check_prop_resp__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   mgmt__check_prop_resp__free_unpacked
                     (Mgmt__CheckPropResp *message,
                      ProtobufCAllocator *allocator);
/* Mgmt__CheckActReq methods */
void   mgmt__check_act_req__init
                     (Mgmt__CheckActReq         *message);
size_t mgmt__check_act_req__get_packed_size
                     (const Mgmt__CheckActReq   *message);
size_t mgmt__check_act_req__pack
                     (const Mgmt__CheckActReq   *message,
                      uint8_t             *out);
size_t mgmt__check_act_req__pack_to_buffer
                     (const Mgmt__CheckActReq   *message,
                      ProtobufCBuffer     *buffer);
Mgmt__CheckActReq *
       mgmt__check_act_req__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   mgmt__check_act_req__free_unpacked
                     (Mgmt__CheckActReq *message,
                      ProtobufCAllocator *allocator);
/* Mgmt__CheckActResp methods */
void   mgmt__check_act_resp__init
                     (Mgmt__CheckActResp         *message);
size_t mgmt__check_act_resp__get_packed_size
                     (const Mgmt__CheckActResp   *message);
size_t mgmt__check_act_resp__pack
                     (const Mgmt__CheckActResp   *message,
                      uint8_t             *out);
size_t mgmt__check_act_resp__pack_to_buffer
                     (const Mgmt__CheckActResp   *message,
                      ProtobufCBuffer     *buffer);
Mgmt__CheckActResp *
       mgmt__check_act_resp__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   mgmt__check_act_resp__free_unpacked
                     (Mgmt__CheckActResp *message,
                      ProtobufCAllocator *allocator);
/* --- per-message closures --- */

typedef void (*Mgmt__CheckInconsistPolicy_Closure)
                 (const Mgmt__CheckInconsistPolicy *message,
                  void *closure_data);
typedef void (*Mgmt__CheckStartReq_Closure)
                 (const Mgmt__CheckStartReq *message,
                  void *closure_data);
typedef void (*Mgmt__CheckStartResp_Closure)
                 (const Mgmt__CheckStartResp *message,
                  void *closure_data);
typedef void (*Mgmt__CheckStopReq_Closure)
                 (const Mgmt__CheckStopReq *message,
                  void *closure_data);
typedef void (*Mgmt__CheckStopResp_Closure)
                 (const Mgmt__CheckStopResp *message,
                  void *closure_data);
typedef void (*Mgmt__CheckQueryReq_Closure)
                 (const Mgmt__CheckQueryReq *message,
                  void *closure_data);
typedef void (*Mgmt__CheckQueryTime_Closure)
                 (const Mgmt__CheckQueryTime *message,
                  void *closure_data);
typedef void (*Mgmt__CheckQueryInconsist_Closure)
                 (const Mgmt__CheckQueryInconsist *message,
                  void *closure_data);
typedef void (*Mgmt__CheckQueryTarget_Closure)
                 (const Mgmt__CheckQueryTarget *message,
                  void *closure_data);
typedef void (*Mgmt__CheckQueryPool_Closure)
                 (const Mgmt__CheckQueryPool *message,
                  void *closure_data);
typedef void (*Mgmt__CheckQueryResp_Closure)
                 (const Mgmt__CheckQueryResp *message,
                  void *closure_data);
typedef void (*Mgmt__CheckPropReq_Closure)
                 (const Mgmt__CheckPropReq *message,
                  void *closure_data);
typedef void (*Mgmt__CheckPropResp_Closure)
                 (const Mgmt__CheckPropResp *message,
                  void *closure_data);
typedef void (*Mgmt__CheckActReq_Closure)
                 (const Mgmt__CheckActReq *message,
                  void *closure_data);
typedef void (*Mgmt__CheckActResp_Closure)
                 (const Mgmt__CheckActResp *message,
                  void *closure_data);

/* --- services --- */


/* --- descriptors --- */

extern const ProtobufCMessageDescriptor mgmt__check_inconsist_policy__descriptor;
extern const ProtobufCMessageDescriptor mgmt__check_start_req__descriptor;
extern const ProtobufCMessageDescriptor mgmt__check_start_resp__descriptor;
extern const ProtobufCMessageDescriptor mgmt__check_stop_req__descriptor;
extern const ProtobufCMessageDescriptor mgmt__check_stop_resp__descriptor;
extern const ProtobufCMessageDescriptor mgmt__check_query_req__descriptor;
extern const ProtobufCMessageDescriptor mgmt__check_query_time__descriptor;
extern const ProtobufCMessageDescriptor mgmt__check_query_inconsist__descriptor;
extern const ProtobufCMessageDescriptor mgmt__check_query_target__descriptor;
extern const ProtobufCMessageDescriptor mgmt__check_query_pool__descriptor;
extern const ProtobufCMessageDescriptor mgmt__check_query_resp__descriptor;
extern const ProtobufCMessageDescriptor mgmt__check_prop_req__descriptor;
extern const ProtobufCMessageDescriptor mgmt__check_prop_resp__descriptor;
extern const ProtobufCMessageDescriptor mgmt__check_act_req__descriptor;
extern const ProtobufCMessageDescriptor mgmt__check_act_resp__descriptor;

PROTOBUF_C__END_DECLS


#endif  /* PROTOBUF_C_check_2eproto__INCLUDED */