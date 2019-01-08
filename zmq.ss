(import :std/foreign)

(export #t)

(begin-ffi (ctx msg ffn socket
            ctx-new ctx-shutdown ctx-term
            msg-init msg-init-size msg-init-data
            msg-send msg-recv msg-close
            msg-data msg-size msg-more
            msg-gets msg-gets msg-set
            msg-copy msg-move
            socket close getsockopt setsockopt-string bind connect
            send recv send-const socket-monitor
            send-string
            errno strerror version
            atomic-counter-new atomic-counter-set
            atomic-counter-inc atomic-counter-dec
            atomic-counter-value atomic-counter-destroy
            ZMQ_VERSION_MAJOR ZMQ_VERSION_MINOR ZMQ_VERSION_PATCH
            EFSM ENOCOMPATPROTO ETERM EMTHREAD
            ZMQ_IO_THREADS ZMQ_MAX_SOCKETS ZMQ_SOCKET_LIMIT
            ZMQ_THREAD_PRIORITY ZMQ_THREAD_SCHED_POLICY
            ZMQ_MAX_MSGSZ ZMQ_MSG_T_SIZE ZMQ_THREAD_AFFINITY_CPU_ADD
            ZMQ_THREAD_AFFINITY_CPU_REMOVE ZMQ_THREAD_NAME_PREFIX
            ZMQ_IO_THREADS_DFLT ZMQ_MAX_SOCKETS_DFLT
            ZMQ_THREAD_PRIORITY_DFLT ZMQ_THREAD_SCHED_POLICY_DFLT
            ZMQ_PAIR ZMQ_PUB ZMQ_SUB ZMQ_REQ ZMQ_REP ZMQ_DEALER
            ZMQ_ROUTER ZMQ_PULL ZMQ_PUSH ZMQ_XPUB ZMQ_XSUB ZMQ_STREAM
            ZMQ_AFFINITY ZMQ_ROUTING_ID ZMQ_SUBSCRIBE ZMQ_UNSUBSCRIBE
            ZMQ_RATE ZMQ_RECOVERY_IVL ZMQ_SNDBUF ZMQ_RCVBUF ZMQ_RCVMORE
            ZMQ_FD ZMQ_EVENTS ZMQ_TYPE ZMQ_LINGER ZMQ_RECONNECT_IVL
            ZMQ_BACKLOG ZMQ_RECONNECT_IVL_MAX ZMQ_MAXMSGSIZE ZMQ_SNDHWM
            ZMQ_RCVHWM ZMQ_MULTICAST_HOPS ZMQ_RCVTIMEO ZMQ_SNDTIMEO
            ZMQ_LAST_ENDPOINT ZMQ_ROUTER_MANDATORY ZMQ_TCP_KEEPALIVE
            ZMQ_TCP_KEEPALIVE_CNT ZMQ_TCP_KEEPALIVE_IDLE
            ZMQ_TCP_KEEPALIVE_INTVL ZMQ_IMMEDIATE ZMQ_XPUB_VERBOSE
            ZMQ_ROUTER_RAW ZMQ_IPV6 ZMQ_MECHANISM ZMQ_PLAIN_SERVER
            ZMQ_PLAIN_USERNAME ZMQ_PLAIN_PASSWORD ZMQ_CURVE_SERVER
            ZMQ_CURVE_PUBLICKEY ZMQ_CURVE_SECRETKEY ZMQ_CURVE_SERVERKEY
            ZMQ_PROBE_ROUTER ZMQ_REQ_CORRELATE ZMQ_REQ_RELAXED ZMQ_CONFLATE
            ZMQ_ZAP_DOMAIN ZMQ_ROUTER_HANDOVER ZMQ_TOS
            ZMQ_CONNECT_ROUTING_ID ZMQ_GSSAPI_SERVER ZMQ_GSSAPI_PRINCIPAL
            ZMQ_GSSAPI_SERVICE_PRINCIPAL ZMQ_GSSAPI_PLAINTEXT
            ZMQ_HANDSHAKE_IVL ZMQ_SOCKS_PROXY ZMQ_XPUB_NODROP ZMQ_BLOCKY
            ZMQ_XPUB_MANUAL ZMQ_XPUB_WELCOME_MSG ZMQ_STREAM_NOTIFY
            ZMQ_INVERT_MATCHING ZMQ_HEARTBEAT_IVL ZMQ_HEARTBEAT_TTL
            ZMQ_HEARTBEAT_TIMEOUT ZMQ_XPUB_VERBOSER ZMQ_CONNECT_TIMEOUT
            ZMQ_TCP_MAXRT ZMQ_THREAD_SAFE ZMQ_MULTICAST_MAXTPDU
            ZMQ_VMCI_BUFFER_SIZE ZMQ_VMCI_BUFFER_MIN_SIZE
            ZMQ_VMCI_BUFFER_MAX_SIZE ZMQ_VMCI_CONNECT_TIMEOUT ZMQ_USE_FD
            ZMQ_GSSAPI_PRINCIPAL_NAMETYPE
            ZMQ_GSSAPI_SERVICE_PRINCIPAL_NAMETYPE ZMQ_BINDTODEVICE
            ZMQ_MORE ZMQ_SHARED ZMQ_DONTWAIT ZMQ_SNDMORE ZMQ_NULL ZMQ_PLAIN
            ZMQ_CURVE ZMQ_GSSAPI ZMQ_GROUP_MAX_LENGTH
            ZMQ_GSSAPI_NT_HOSTBASED ZMQ_GSSAPI_NT_USER_NAME
            ZMQ_GSSAPI_NT_KRB5_PRINCIPAL ZMQ_EVENT_CONNECTED
            ZMQ_EVENT_CONNECT_DELAYED ZMQ_EVENT_CONNECT_RETRIED
            ZMQ_EVENT_LISTENING ZMQ_EVENT_BIND_FAILED ZMQ_EVENT_ACCEPTED
            ZMQ_EVENT_ACCEPT_FAILED ZMQ_EVENT_CLOSED ZMQ_EVENT_CLOSE_FAILED
            ZMQ_EVENT_DISCONNECTED ZMQ_EVENT_MONITOR_STOPPED ZMQ_EVENT_ALL
            ZMQ_EVENT_HANDSHAKE_FAILED_NO_DETAIL
            ZMQ_EVENT_HANDSHAKE_SUCCEEDED
            ZMQ_EVENT_HANDSHAKE_FAILED_PROTOCOL
            ZMQ_EVENT_HANDSHAKE_FAILED_AUTH
            ZMQ_PROTOCOL_ERROR_ZMTP_UNSPECIFIED
            ZMQ_PROTOCOL_ERROR_ZMTP_UNEXPECTED_COMMAND
            ZMQ_PROTOCOL_ERROR_ZMTP_INVALID_SEQUENCE
            ZMQ_PROTOCOL_ERROR_ZMTP_KEY_EXCHANGE
            ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_UNSPECIFIED
            ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_MESSAGE
            ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_HELLO
            ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_INITIATE
            ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_ERROR
            ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_READY
            ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_WELCOME
            ZMQ_PROTOCOL_ERROR_ZMTP_INVALID_METADATA
            ZMQ_PROTOCOL_ERROR_ZMTP_CRYPTOGRAPHIC
            ZMQ_PROTOCOL_ERROR_ZMTP_MECHANISM_MISMATCH
            ZMQ_PROTOCOL_ERROR_ZAP_UNSPECIFIED
            ZMQ_PROTOCOL_ERROR_ZAP_MALFORMED_REPLY
            ZMQ_PROTOCOL_ERROR_ZAP_BAD_REQUEST_ID
            ZMQ_PROTOCOL_ERROR_ZAP_BAD_VERSION
            ZMQ_PROTOCOL_ERROR_ZAP_INVALID_STATUS_CODE
            ZMQ_PROTOCOL_ERROR_ZAP_INVALID_METADATA
)

  (c-declare "#include <string.h>")
  (c-declare "#include <zmq.h>")
  (c-define-type ctx (pointer void))
  (c-define-type msg (pointer "zmq_msg_t"))
  (c-define-type socket (pointer void))
  (c-define-type counter (pointer void))

  (c-define-type ffn (function ((pointer void) (pointer void)) void))

  ;; Contexts

  (define-c-lambda ctx-new () ctx "zmq_ctx_new")
  (define-c-lambda ctx-shutdown (ctx) int "zmq_ctx_shutdown")
  (define-c-lambda ctx-term (ctx) int "zmq_ctx_term")

  ;; Messages

  (define-c-lambda msg-init-size (msg) int "zmq_msg_init")
  (define-c-lambda msg-init-size (msg size_t) int "zmq_msg_init_size")

  (define-c-lambda msg-init-data
    (msg (pointer void) size_t ffn (pointer void))
    int
    "zmq_msg_init_data")

  (define-c-lambda msg-send (msg socket int) int "zmq_msg_send")
  (define-c-lambda msg-recv (msg socket int) int "zmq_msg_recv")
  (define-c-lambda msg-close (msg) int "zmq_msg_close")

  (define-c-lambda msg-data (msg) (pointer void) "zmq_msg_data")
  (define-c-lambda msg-size (msg) size_t "zmq_msg_size")
  (define-c-lambda msg-more (msg) int "zmq_msg_more")

  (define-c-lambda msg-gets
    (msg char-string)
    char-string
    "___return((char *)zmq_msg_gets(___arg1, ___arg2));")

  (define-c-lambda msg-get (msg int) int "zmq_msg_get")
  (define-c-lambda msg-set (msg int int) int "zmq_msg_set")
  (define-c-lambda msg-copy (msg msg) int "zmq_msg_copy")
  (define-c-lambda msg-move (msg msg) int "zmq_msg_move")

  ;; Sockets

  (define-c-lambda socket (ctx int) socket "zmq_socket")
  (define-c-lambda close (socket) int "zmq_close")

  (define-c-lambda getsockopt
    (socket int (pointer void) (pointer size_t))
    int
    "zmq_getsockopt")

  (define-c-lambda setsockopt
    (socket int (pointer void) size_t)
    int
    "zmq_setsockopt")

  (define-c-lambda setsockopt-string
    (socket int char-string)
    int
    #<<END-C
    ___return(zmq_setsockopt(___arg1,
                             ___arg2,
                             (void *)___arg3,
                             strlen(___arg3)));
END-C
)  
  (define-c-lambda bind (socket char-string) int "zmq_bind")
  (define-c-lambda connect (socket char-string) int "zmq_connect")

  (define-c-lambda send (socket (pointer void) size_t int) int "zmq_send")
  (define-c-lambda recv (socket (pointer void) size_t int) int "zmq_recv")

  (define-c-lambda send-string (socket char-string int) int
    #<<END-C
    ___return(zmq_send(___arg1, ___arg2, strlen(___arg2), ___arg3));
END-C
)

  (define-c-lambda recv-string (socket int int) char-string
    #<<END-C

char *s = (char *)malloc(___arg2+1);
int ret;
if (s != NULL) {
  ret = zmq_recv(___arg1, s, ___arg2, ___arg3);
  if (ret == -1) {
    ___return(NULL);
  } else {
    s[ret] = '\0';
    ___return(s);
  }
___return(NULL);
}
#define ___AT_END if (s != NULL) free(s);

END-C
)
  
  (define-c-lambda send-const
    (socket (pointer void) size_t int)
    int
    "zmq_send_const")

  (define-c-lambda socket-monitor
    (socket char-string int)
    int
    "zmq_socket_monitor")

  ;; Errors and versions

  (define-c-lambda errno () int "zmq_errno")

  (define-c-lambda strerror
    (int)
    char-string
    "___return((char *)zmq_strerror(___arg1));")

  (define-c-lambda version
    ((pointer int) (pointer int) (pointer int))
    void
    "zmq_version")

  ;; Atomic counters

  (define-c-lambda atomic-counter-new () counter "zmq_atomic_counter_new")

  (define-c-lambda atomic-counter-set
    (counter int)
    void
    "zmq_atomic_counter_set")

  (define-c-lambda atomic-counter-inc (counter) int "zmq_atomic_counter_inc")
  (define-c-lambda atomic-counter-dec (counter) int "zmq_atomic_counter_dec")

  (define-c-lambda atomic-counter-value
    (counter)
    int
    "zmq_atomic_counter_value")

  (define-c-lambda atomic-counter-destroy
    ((pointer counter))
    void
    "zmq_atomic_counter_destroy")

  ;; Constants

  (define-const ZMQ_VERSION_MAJOR)
  (define-const ZMQ_VERSION_MINOR)
  (define-const ZMQ_VERSION_PATCH)

  (define-const EFSM)
  (define-const ENOCOMPATPROTO)
  (define-const ETERM)
  (define-const EMTHREAD)

  (define-const ZMQ_IO_THREADS)
  (define-const ZMQ_MAX_SOCKETS)
  (define-const ZMQ_SOCKET_LIMIT)
  (define-const ZMQ_THREAD_PRIORITY)
  (define-const ZMQ_THREAD_SCHED_POLICY)
  (define-const ZMQ_MAX_MSGSZ)
  (define-const ZMQ_MSG_T_SIZE)
  (define-const ZMQ_THREAD_AFFINITY_CPU_ADD)
  (define-const ZMQ_THREAD_AFFINITY_CPU_REMOVE)
  (define-const ZMQ_THREAD_NAME_PREFIX)

  (define-const ZMQ_IO_THREADS_DFLT)
  (define-const ZMQ_MAX_SOCKETS_DFLT)
  (define-const ZMQ_THREAD_PRIORITY_DFLT)
  (define-const ZMQ_THREAD_SCHED_POLICY_DFLT)

  (define-const ZMQ_PAIR)
  (define-const ZMQ_PUB)
  (define-const ZMQ_SUB)
  (define-const ZMQ_REQ)
  (define-const ZMQ_REP)
  (define-const ZMQ_DEALER)
  (define-const ZMQ_ROUTER)
  (define-const ZMQ_PULL)
  (define-const ZMQ_PUSH)
  (define-const ZMQ_XPUB)
  (define-const ZMQ_XSUB)
  (define-const ZMQ_STREAM)

  (define-const ZMQ_AFFINITY)
  (define-const ZMQ_ROUTING_ID)
  (define-const ZMQ_SUBSCRIBE)
  (define-const ZMQ_UNSUBSCRIBE)
  (define-const ZMQ_RATE)
  (define-const ZMQ_RECOVERY_IVL)
  (define-const ZMQ_SNDBUF)
  (define-const ZMQ_RCVBUF)
  (define-const ZMQ_RCVMORE)
  (define-const ZMQ_FD)
  (define-const ZMQ_EVENTS)
  (define-const ZMQ_TYPE)
  (define-const ZMQ_LINGER)
  (define-const ZMQ_RECONNECT_IVL)
  (define-const ZMQ_BACKLOG)
  (define-const ZMQ_RECONNECT_IVL_MAX)
  (define-const ZMQ_MAXMSGSIZE)
  (define-const ZMQ_SNDHWM)
  (define-const ZMQ_RCVHWM)
  (define-const ZMQ_MULTICAST_HOPS)
  (define-const ZMQ_RCVTIMEO)
  (define-const ZMQ_SNDTIMEO)
  (define-const ZMQ_LAST_ENDPOINT)
  (define-const ZMQ_ROUTER_MANDATORY)
  (define-const ZMQ_TCP_KEEPALIVE)
  (define-const ZMQ_TCP_KEEPALIVE_CNT)
  (define-const ZMQ_TCP_KEEPALIVE_IDLE)
  (define-const ZMQ_TCP_KEEPALIVE_INTVL)
  (define-const ZMQ_IMMEDIATE)
  (define-const ZMQ_XPUB_VERBOSE)
  (define-const ZMQ_ROUTER_RAW)
  (define-const ZMQ_IPV6)
  (define-const ZMQ_MECHANISM)
  (define-const ZMQ_PLAIN_SERVER)
  (define-const ZMQ_PLAIN_USERNAME)
  (define-const ZMQ_PLAIN_PASSWORD)
  (define-const ZMQ_CURVE_SERVER)
  (define-const ZMQ_CURVE_PUBLICKEY)
  (define-const ZMQ_CURVE_SECRETKEY)
  (define-const ZMQ_CURVE_SERVERKEY)
  (define-const ZMQ_PROBE_ROUTER)
  (define-const ZMQ_REQ_CORRELATE)
  (define-const ZMQ_REQ_RELAXED)
  (define-const ZMQ_CONFLATE)
  (define-const ZMQ_ZAP_DOMAIN)
  (define-const ZMQ_ROUTER_HANDOVER)
  (define-const ZMQ_TOS)
  (define-const ZMQ_CONNECT_ROUTING_ID)
  (define-const ZMQ_GSSAPI_SERVER)
  (define-const ZMQ_GSSAPI_PRINCIPAL)
  (define-const ZMQ_GSSAPI_SERVICE_PRINCIPAL)
  (define-const ZMQ_GSSAPI_PLAINTEXT)
  (define-const ZMQ_HANDSHAKE_IVL)
  (define-const ZMQ_SOCKS_PROXY)
  (define-const ZMQ_XPUB_NODROP)
  (define-const ZMQ_BLOCKY)
  (define-const ZMQ_XPUB_MANUAL)
  (define-const ZMQ_XPUB_WELCOME_MSG)
  (define-const ZMQ_STREAM_NOTIFY)
  (define-const ZMQ_INVERT_MATCHING)
  (define-const ZMQ_HEARTBEAT_IVL)
  (define-const ZMQ_HEARTBEAT_TTL)
  (define-const ZMQ_HEARTBEAT_TIMEOUT)
  (define-const ZMQ_XPUB_VERBOSER)
  (define-const ZMQ_CONNECT_TIMEOUT)
  (define-const ZMQ_TCP_MAXRT)
  (define-const ZMQ_THREAD_SAFE)
  (define-const ZMQ_MULTICAST_MAXTPDU)
  (define-const ZMQ_VMCI_BUFFER_SIZE)
  (define-const ZMQ_VMCI_BUFFER_MIN_SIZE)
  (define-const ZMQ_VMCI_BUFFER_MAX_SIZE)
  (define-const ZMQ_VMCI_CONNECT_TIMEOUT)
  (define-const ZMQ_USE_FD)
  (define-const ZMQ_GSSAPI_PRINCIPAL_NAMETYPE)
  (define-const ZMQ_GSSAPI_SERVICE_PRINCIPAL_NAMETYPE)
  (define-const ZMQ_BINDTODEVICE)

  (define-const ZMQ_GSSAPI_NT_HOSTBASED)
  (define-const ZMQ_GSSAPI_NT_USER_NAME)
  (define-const ZMQ_GSSAPI_NT_KRB5_PRINCIPAL)
  (define-const ZMQ_EVENT_CONNECTED)
  (define-const ZMQ_EVENT_CONNECT_DELAYED)
  (define-const ZMQ_EVENT_CONNECT_RETRIED)
  (define-const ZMQ_EVENT_LISTENING)
  (define-const ZMQ_EVENT_BIND_FAILED)
  (define-const ZMQ_EVENT_ACCEPTED)
  (define-const ZMQ_EVENT_ACCEPT_FAILED)
  (define-const ZMQ_EVENT_CLOSED)
  (define-const ZMQ_EVENT_CLOSE_FAILED)
  (define-const ZMQ_EVENT_DISCONNECTED)
  (define-const ZMQ_EVENT_MONITOR_STOPPED)
  (define-const ZMQ_EVENT_ALL)
  (define-const ZMQ_EVENT_HANDSHAKE_FAILED_NO_DETAIL)
  (define-const ZMQ_EVENT_HANDSHAKE_SUCCEEDED)
  (define-const ZMQ_EVENT_HANDSHAKE_FAILED_PROTOCOL)
  (define-const ZMQ_EVENT_HANDSHAKE_FAILED_AUTH)
  (define-const ZMQ_PROTOCOL_ERROR_ZMTP_UNSPECIFIED)
  (define-const ZMQ_PROTOCOL_ERROR_ZMTP_UNEXPECTED_COMMAND)
  (define-const ZMQ_PROTOCOL_ERROR_ZMTP_INVALID_SEQUENCE)
  (define-const ZMQ_PROTOCOL_ERROR_ZMTP_KEY_EXCHANGE)
  (define-const ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_UNSPECIFIED)
  (define-const ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_MESSAGE)
  (define-const ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_HELLO)
  (define-const ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_INITIATE)
  (define-const ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_ERROR)
  (define-const ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_READY)
  (define-const ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_WELCOME)
  (define-const ZMQ_PROTOCOL_ERROR_ZMTP_INVALID_METADATA)
  (define-const ZMQ_PROTOCOL_ERROR_ZMTP_CRYPTOGRAPHIC)
  (define-const ZMQ_PROTOCOL_ERROR_ZMTP_MECHANISM_MISMATCH)
  (define-const ZMQ_PROTOCOL_ERROR_ZAP_UNSPECIFIED)
  (define-const ZMQ_PROTOCOL_ERROR_ZAP_MALFORMED_REPLY)
  (define-const ZMQ_PROTOCOL_ERROR_ZAP_BAD_REQUEST_ID)
  (define-const ZMQ_PROTOCOL_ERROR_ZAP_BAD_VERSION)
  (define-const ZMQ_PROTOCOL_ERROR_ZAP_INVALID_STATUS_CODE)
  (define-const ZMQ_PROTOCOL_ERROR_ZAP_INVALID_METADATA)

  (define-const ZMQ_MORE)
  (define-const ZMQ_SHARED)

  (define-const ZMQ_DONTWAIT)
  (define-const ZMQ_SNDMORE)

  (define-const ZMQ_NULL)
  (define-const ZMQ_PLAIN)
  (define-const ZMQ_CURVE)
  (define-const ZMQ_GSSAPI)

  (define-const ZMQ_GROUP_MAX_LENGTH))

(def (subscribe s filter)
  (setsockopt-string s ZMQ_SUBSCRIBE filter))

(def (unsubscribe s filter)
  (setsockopt-string s ZMQ_UNSUBSCRIBE filter))
