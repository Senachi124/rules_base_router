#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
typedef struct RBEngine RBEngine;
/* Threading and ownership contract:
 * - Serialize every operation on one engine; it is not a concurrent C API.
 * - Input strings are NUL-terminated UTF-8; buffers remain valid for the call.
 * - Own returned strings until rb_string_free; own engines until rb_engine_free.
 * - Drain events regularly. Callbacks borrow their buffers, must copy retained
 *   data, and must not re-enter or destroy the engine during rb_engine_drain.
 * - Negative intptr_t results indicate failure; TCP writes may accept fewer
 *   bytes (including zero). Retry the remainder only after driving the engine.
 * - TCP/UDP receive events pause delivery for that flow until rb_engine_resume.
 * - kind 8 / flow 0 is fatal: stop transport and recreate the engine.
 * - There is deliberately no direct-connection fallback anywhere in this API.
 */
char *rb_profile_inspect(const char *profile);
char *rb_policy_validate(const char *policy);
char *rb_policy_evaluate(const char *policy, const char *flow);
void rb_string_free(char *string);
RBEngine *rb_engine_new(const char *profile, bool raw);
void rb_engine_free(RBEngine *engine);
intptr_t rb_engine_start(RBEngine *engine);
intptr_t rb_engine_tick(RBEngine *engine, int64_t milliseconds);
intptr_t rb_engine_receive(RBEngine *engine, const uint8_t *data, size_t length);
intptr_t rb_engine_feed_ip(RBEngine *engine, const uint8_t *data, size_t length);
intptr_t rb_engine_open_tcp(RBEngine *engine, uint64_t flow, const char *ip, uint16_t port);
intptr_t rb_engine_tcp_write(RBEngine *engine, uint64_t flow, const uint8_t *data, size_t length);
intptr_t rb_engine_tcp_eof(RBEngine *engine, uint64_t flow);
intptr_t rb_engine_resume(RBEngine *engine, uint64_t flow);
intptr_t rb_engine_open_udp(RBEngine *engine, uint64_t flow);
intptr_t rb_engine_udp_send(RBEngine *engine, uint64_t flow, const char *ip, uint16_t port, const uint8_t *data, size_t length);
intptr_t rb_engine_close(RBEngine *engine, uint64_t flow);
int64_t rb_engine_handshake_age(RBEngine *engine);
intptr_t rb_engine_flow_count(RBEngine *engine);
uint64_t rb_engine_authenticated_rx_count(RBEngine *engine);
typedef void (*RBEventCallback)(void *context, uint32_t kind, uint64_t flow, const char *ip, uint16_t port, const uint8_t *data, size_t length);
intptr_t rb_engine_drain(RBEngine *engine, RBEventCallback callback, void *context);
