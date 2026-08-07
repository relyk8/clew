/* ***************************************************************************
 * drtrace.c  --  Clew Channel 3: API-tracing + comparison-logging DR client
 *
 * Built for DynamoRIO 11.91.20651, 32-bit (target guest is PE32 / x86).
 * MSVC only: DynamoRIO's CMake refuses any other compiler on Windows, so this
 * builds on Windows rather than on the Linux analysis host (see BUILD_RECIPE.md).
 * The DynamoRIO API calls below follow the 11.91.20651 headers and the shipped
 * samples (wrap.c, instrcalls.c, memtrace_simple.c).
 *
 * WHAT IT DOES
 *   Successor to cmplog.c. It still logs the runtime operands of every executed
 *   OP_cmp / OP_test, and adds three things that make Channel 3 a candidate
 *   *producer* rather than an annotator of Channel 2's call sites:
 *
 *     1. API tracing (drwrap). Every environment-sensitive API in api_table.h
 *        is wrapped; the pre-callback logs the call site and arguments, the
 *        post-callback the return value and any out-parameter that became
 *        readable text. Return values and out-params are values that do not
 *        exist anywhere in the binary -- no static tool can recover them.
 *     2. A module table. Each module load is logged with its runtime extent, so
 *        the host rebases PCs itself instead of being handed --module-base.
 *     3. A global monotonic sequence number on every record, so the host can
 *        join a comparison to the API return that produced its operand rather
 *        than inferring it from PC proximity.
 *
 *   Plus the cmp->jcc decode: a cmp sets flags but does not say what the
 *   comparison meant; the conditional jump that consumes those flags does.
 *
 * DESIGN (correctness-first, modeled on the DR samples)
 *   - Per-thread text log for call/return/comparison records; one process-wide
 *     file for the module table (module loads can arrive before a given
 *     thread's TLS slot is initialized, and one copy of the table is enough).
 *   - We FLUSH after every record. REQUIRED: CAPE kills the target at the
 *     analysis timeout, so anything not already on disk is lost (the "drcov
 *     flush caveat" -- drcov only wrote on clean exit, giving 0-byte logs).
 *   - Strings are hex-encoded. Not cosmetic: these bytes come from memory the
 *     sample controls, and the host parser treats the log as trusted input. As
 *     literal text a sample could embed a newline and a well-formed record in a
 *     string argument and inject fabricated comparisons into our output.
 *
 * FUTURE (documented, not implemented here)
 *   - Additional comparison-class opcodes: OP_sub, the cmov* / set* families,
 *     OP_cmpxchg, string compares (OP_cmps*), OP_bt*, OP_ucomiss.
 *   - Inlined buffering (memtrace-style) instead of a per-cmp clean call.
 *   - Per-API argument arity, which would remove the fixed-slot argument read.
 * ***************************************************************************/

#include "dr_api.h"
#include "drmgr.h"
#include "drwrap.h"
#include <string.h> /* strcmp, strlen */

#include "api_table.h" /* GENERATED from clew/tiers.py -- see gen_api_table.py */

/* element count of a fixed-size buffer (utils.h defines this, but we don't link
 * utils.c -- keep drtrace.c self-contained). */
#define BUFFER_SIZE_ELEMENTS(buf) (sizeof(buf) / sizeof((buf)[0]))

/* ---- tunables (all overridable as client options; see dr_client_main) ---- */

/* Argument slots read per call. The client carries no per-API arity, so reads
 * past a function's real argument count return whatever is on the stack and the
 * host filters them. 8 covers the widest target in the set:
 * GetVolumeInformationW, whose volume serial is arg 3 and fs name arg 6. */
#define DRTRACE_MAX_ARGS 16
static int num_args = 8;

/* Bytes read and logged for a dereferenced string. */
#define DRTRACE_MAX_STR_BYTES 128

/* Minimum characters before a readable run counts as a string. Below ~4 the
 * false-positive rate from non-pointer arguments climbs sharply. */
static int min_str_chars = 4;

/* Calls logged per (API, call site) pair; 0 disables the cap. Bounds a
 * GetTickCount timing loop without bounding the interesting APIs. */
static int max_hits = 64;

/* Instructions scanned forward from a cmp looking for the jcc that consumes its
 * flags. The jcc is usually adjacent; a handful covers a scheduled load. */
#define DRTRACE_JCC_SCAN 4

/* Cap on bytes read + printed for a memory operand of a comparison. Target is
 * 32-bit, so pointer-sized covers the common widths (1/2/4). */
#define DRTRACE_MAX_MEM_BYTES sizeof(reg_t)

/* Default log directory inside the guest. The CAPE package (exe_drtrace.py)
 * also creates this; we attempt it here too so a manual drrun works standalone.
 * Overridable via "-logdir <dir>". */
static char logdir[MAXIMUM_PATH] = "C:\\drtrace_logs";

static int tls_idx;      /* drmgr TLS slot holding the per-thread file_t */
static client_id_t my_id;

/* Module table: one process-wide file, guarded because several threads can load
 * modules concurrently. */
static file_t module_file = INVALID_FILE;
static void *module_lock;

/* Global record ordering, shared across threads and record types. This is what
 * lets the host bind a comparison to the API return that produced its operand.
 * A 32-bit counter wraps after ~2.1e9 records; a real analysis produces tens of
 * thousands, so wrap is not a practical concern. */
static volatile int global_seq;

static int
next_seq(void)
{
    return dr_atomic_add32_return_sum(&global_seq, 1);
}

/* -------------------------------------------------------------------------- */
/* hit caps                                                                    */
/* -------------------------------------------------------------------------- */

/* Open-addressed fixed table. Never resizes: if a probe chain fills up we
 * degrade to logging everything rather than silently dropping records. */
#define DRTRACE_HITCAP_SLOTS 8192
#define DRTRACE_HITCAP_PROBES 16

typedef struct {
    app_pc site;
    int api_idx;
    uint count;
    bool used;
    bool reported;
} hitcap_entry_t;

static hitcap_entry_t hitcap[DRTRACE_HITCAP_SLOTS];
static void *hitcap_lock;

/* Whether this (API, call site) pair may still log. On the transition to capped
 * it emits the marker once, so truncation is reported rather than silent. */
static bool
hitcap_allow(file_t f, int api_idx, app_pc site)
{
    uint h;
    int probe;
    bool allow = true;

    if (max_hits <= 0)
        return true;

    h = (uint)((((ptr_uint_t)site >> 2) ^ ((ptr_uint_t)api_idx << 13)) % DRTRACE_HITCAP_SLOTS);
    dr_mutex_lock(hitcap_lock);
    for (probe = 0; probe < DRTRACE_HITCAP_PROBES; probe++) {
        hitcap_entry_t *e = &hitcap[(h + probe) % DRTRACE_HITCAP_SLOTS];
        if (!e->used) {
            e->used = true;
            e->site = site;
            e->api_idx = api_idx;
            e->count = 1;
            break;
        }
        if (e->site == site && e->api_idx == api_idx) {
            if (e->count >= (uint)max_hits) {
                allow = false;
                if (!e->reported) {
                    e->reported = true;
                    dr_fprintf(f, "# capped api=%s site=" PFX " after %d calls\n",
                               drtrace_api_names[api_idx], site, max_hits);
                    dr_flush_file(f);
                }
            } else {
                e->count++;
            }
            break;
        }
        /* slot taken by a different pair -- keep probing */
    }
    dr_mutex_unlock(hitcap_lock);
    return allow;
}

/* -------------------------------------------------------------------------- */
/* string capture                                                              */
/* -------------------------------------------------------------------------- */

static void
emit_hex(file_t f, const byte *buf, size_t n)
{
    static const char hexd[] = "0123456789abcdef";
    char out[2 * DRTRACE_MAX_STR_BYTES + 1];
    size_t i;

    if (n > DRTRACE_MAX_STR_BYTES)
        n = DRTRACE_MAX_STR_BYTES;
    for (i = 0; i < n; i++) {
        out[2 * i] = hexd[(buf[i] >> 4) & 0xf];
        out[2 * i + 1] = hexd[buf[i] & 0xf];
    }
    out[2 * n] = '\0';
    dr_fprintf(f, "%s", out);
}

/* Classify a byte run as text. Returns 'A' (ascii), 'W' (utf-16le), or 0 for
 * "not a string"; *out_bytes is the raw byte count to log.
 *
 * This is deliberately a heuristic over an observation -- "these bytes read as
 * text" -- not a claim about the argument's type. The raw pointer is always
 * logged next to it so the analyst can see what the reading was derived from. A
 * wide string stops the ascii scan at its first NUL high byte, so the two tests
 * do not fight over the same buffer. */
static char
classify_string(const byte *buf, size_t got, size_t *out_bytes)
{
    size_t i;

    for (i = 0; i < got && buf[i] != 0; i++) {
        if (buf[i] < 0x20 || buf[i] > 0x7e)
            break;
    }
    /* NUL-terminated, or a long printable run that filled the buffer. */
    if (i >= (size_t)min_str_chars && (i == got || buf[i] == 0)) {
        *out_bytes = i;
        return 'A';
    }

    for (i = 0; i + 1 < got; i += 2) {
        if (buf[i] == 0 && buf[i + 1] == 0)
            break;
        if (buf[i] < 0x20 || buf[i] > 0x7e || buf[i + 1] != 0)
            return 0;
    }
    if (i / 2 >= (size_t)min_str_chars) {
        *out_bytes = i;
        return 'W';
    }
    return 0;
}

/* If `val` points at readable text, log it as <tag><idx>=<A|W>:<hex>. */
static void
maybe_log_string(file_t f, const char *tag, int idx, ptr_uint_t val)
{
    byte buf[DRTRACE_MAX_STR_BYTES + 2];
    size_t got = 0, nbytes = 0;
    char kind;

    if (val == 0)
        return;
    /* dr_safe_read does not fault on an unmapped address. A partial read still
     * sets got, so trust got rather than the return value. */
    dr_safe_read((void *)val, sizeof(buf), buf, &got);
    if (got < 2)
        return;
    kind = classify_string(buf, got, &nbytes);
    if (kind == 0)
        return;
    dr_fprintf(f, " %s%d=%c:", tag, idx, kind);
    emit_hex(f, buf, nbytes);
}

/* -------------------------------------------------------------------------- */
/* comparison logging                                                          */
/* -------------------------------------------------------------------------- */

static bool
is_compare_opcode(int opc)
{
    /* OP_cmp and OP_test both set flags from a comparison/AND and are the
     * canonical evasion-check primitives. Start narrow for signal-to-noise. */
    return opc == OP_cmp || opc == OP_test;
}

/* Name of the conditional jump that consumes this comparison's flags, or NULL.
 *
 * A cmp sets flags but does not say what the comparison meant -- `je` means the
 * check was ==, `jl` means <. Walk forward from the comparison: the first
 * conditional branch is the consumer. Give up on anything that rewrites the
 * arithmetic flags first (the jcc would then belong to some other comparison)
 * or on any transfer of control, rather than mis-attribute an operator. */
static const char *
following_jcc_name(void *drcontext, app_pc pc)
{
    instr_noalloc_t noalloc;
    instr_t *instr;
    app_pc next;
    int i;

    next = decode_next_pc(drcontext, pc);
    if (next == NULL)
        return NULL;

    for (i = 0; i < DRTRACE_JCC_SCAN; i++) {
        byte probe[16];
        size_t got = 0;

        /* Confirm the bytes are readable before decoding: the scan can run past
         * the end of a mapped region. Conservative -- a short read near a page
         * boundary just means no operator is attributed. */
        dr_safe_read(next, sizeof(probe), probe, &got);
        if (got < sizeof(probe))
            return NULL;

        instr_noalloc_init(drcontext, &noalloc);
        instr = instr_from_noalloc(&noalloc);
        next = decode(drcontext, next, instr);
        if (next == NULL)
            return NULL;
        if (instr_is_cbr(instr))
            return decode_opcode_name(instr_get_opcode(instr));
        if (instr_is_call(instr) || instr_is_return(instr) || instr_is_ubr(instr))
            return NULL;
        if ((instr_get_arith_flags(instr, DR_QUERY_DEFAULT) & EFLAGS_WRITE_ARITH) != 0)
            return NULL;
    }
    return NULL;
}

/* Clean-call target: reconstruct the comparison at `pc` and log live operands. */
static void
at_compare(app_pc pc)
{
    void *drcontext = dr_get_current_drcontext();
    file_t f = (file_t)(ptr_uint_t)drmgr_get_tls_field(drcontext, tls_idx);
    dr_mcontext_t mc;
    instr_noalloc_t noalloc; /* heap-free decode buffer (safe in a clean call) */
    instr_t *instr;
    const char *jcc;
    int nsrcs, i, opc;

    if (f == INVALID_FILE)
        return;

    /* reg_get_value / opnd_compute_address require DR_MC_CONTROL|DR_MC_INTEGER. */
    mc.size = sizeof(mc);
    mc.flags = DR_MC_CONTROL | DR_MC_INTEGER;
    if (!dr_get_mcontext(drcontext, &mc))
        return;

    instr_noalloc_init(drcontext, &noalloc);
    instr = instr_from_noalloc(&noalloc);
    if (decode(drcontext, pc, instr) == NULL)
        return;

    opc = instr_get_opcode(instr);
    dr_fprintf(f, "T%u pc=" PFX " %s seq=%d", (uint)dr_get_thread_id(drcontext), pc,
               decode_opcode_name(opc), next_seq());

    jcc = following_jcc_name(drcontext, pc);
    if (jcc != NULL)
        dr_fprintf(f, " jcc=%s", jcc);

    nsrcs = instr_num_srcs(instr);
    for (i = 0; i < nsrcs; i++) {
        opnd_t op = instr_get_src(instr, i);
        if (opnd_is_reg(op)) {
            reg_id_t r = opnd_get_reg(op);
            reg_t v = reg_get_value(r, &mc); /* GPRs only */
            dr_fprintf(f, " src%d=reg:%s=" PIFX, i, get_register_name(r), (ptr_uint_t)v);
        } else if (opnd_is_immed_int(op)) {
            ptr_int_t v = opnd_get_immed_int(op);
            dr_fprintf(f, " src%d=imm=" PIFX, i, (ptr_uint_t)v);
        } else if (opnd_is_memory_reference(op)) {
            app_pc addr = opnd_compute_address(op, &mc);
            uint sz = opnd_size_in_bytes(opnd_get_size(op));
            reg_t val = 0;
            size_t got = 0;
            if (sz == 0 || sz > DRTRACE_MAX_MEM_BYTES)
                sz = (uint)DRTRACE_MAX_MEM_BYTES;
            if (addr != NULL && dr_safe_read(addr, sz, &val, &got) && got > 0)
                dr_fprintf(f, " src%d=mem[" PFX "]=" PIFX, i, addr, (ptr_uint_t)val);
            else
                dr_fprintf(f, " src%d=mem[" PFX "]=<unreadable>", i, addr);
        } else {
            /* pc-relative, far, float/SIMD, etc. -- out of scope. */
            dr_fprintf(f, " src%d=other", i);
        }
    }
    dr_fprintf(f, "\n");
    dr_flush_file(f); /* REQUIRED: survive the CAPE timeout-kill */
}

/* drmgr insertion-stage callback (analysis_func was NULL at registration). */
static dr_emit_flags_t
event_app_instruction(void *drcontext, void *tag, instrlist_t *bb, instr_t *instr,
                      bool for_trace, bool translating, void *user_data)
{
    int opc;

    /* Only real application instructions (skip DR/other-client meta and the
     * label/emulation markers drmgr can insert). */
    if (!instr_is_app(instr))
        return DR_EMIT_DEFAULT;

    opc = instr_get_opcode(instr);
    if (is_compare_opcode(opc)) {
        app_pc pc = instr_get_app_pc(instr);
        if (pc != NULL) {
            /* Pass the app PC as a pointer-sized immediate; at_compare re-decodes
             * there and reads the live mcontext.
             * NOTE: plain dr_insert_clean_call stores app state on the DR stack for
             * dr_get_mcontext(). DR_CLEANCALL_READS_APP_CONTEXT (the _ex form) is
             * only needed with drreg register reservation, which we do not use. */
            dr_insert_clean_call(drcontext, bb, instr, (void *)at_compare,
                                 false /*no fpstate*/, 1, OPND_CREATE_INTPTR((ptr_int_t)pc));
        }
    }
    return DR_EMIT_DEFAULT;
}

/* -------------------------------------------------------------------------- */
/* API tracing                                                                 */
/* -------------------------------------------------------------------------- */

/* Carried from the pre-callback to the post-callback. drwrap_get_arg is
 * pre-only (drwrap.h L609: "To access argument values in a post-function
 * callback, store them in the user_data parameter"), so the raw argument values
 * are stashed here to be re-read after the call for out-parameters. */
typedef struct {
    int api_idx;
    app_pc site;
    ptr_uint_t args[DRTRACE_MAX_ARGS];
} call_ctx_t;

static void
wrap_pre(void *wrapcxt, void **user_data)
{
    void *drcontext = dr_get_current_drcontext();
    file_t f = (file_t)(ptr_uint_t)drmgr_get_tls_field(drcontext, tls_idx);
    /* drwrap_wrap_ex passed the API's index as the initial *user_data. */
    int api_idx = (int)(ptr_int_t)*user_data;
    app_pc site = drwrap_get_retaddr(wrapcxt);
    call_ctx_t *ctx;
    int i;

    *user_data = NULL; /* post frees only what we hand it */
    if (f == INVALID_FILE)
        return;
    if (!hitcap_allow(f, api_idx, site))
        return;

    ctx = (call_ctx_t *)dr_thread_alloc(drcontext, sizeof(*ctx));
    if (ctx == NULL)
        return;
    ctx->api_idx = api_idx;
    ctx->site = site;
    for (i = 0; i < num_args; i++)
        ctx->args[i] = (ptr_uint_t)drwrap_get_arg(wrapcxt, i);
    *user_data = ctx;

    /* site is drwrap_get_retaddr: the address in the CALLER the API returns to,
     * i.e. the call site. That is what joins this observation to a static
     * candidate's call_site_va. */
    dr_fprintf(f, "C seq=%d T%u api=%s site=" PFX, next_seq(),
               (uint)dr_get_thread_id(drcontext), drtrace_api_names[api_idx], site);
    for (i = 0; i < num_args; i++) {
        dr_fprintf(f, " a%d=" PIFX, i, ctx->args[i]);
        maybe_log_string(f, "s", i, ctx->args[i]);
    }
    dr_fprintf(f, "\n");
    dr_flush_file(f);
}

static void
wrap_post(void *wrapcxt, void *user_data)
{
    void *drcontext = dr_get_current_drcontext();
    call_ctx_t *ctx = (call_ctx_t *)user_data;
    file_t f;
    int i;

    if (ctx == NULL)
        return; /* pre declined to log: capped, or no log file */

    f = (file_t)(ptr_uint_t)drmgr_get_tls_field(drcontext, tls_idx);

    /* wrapcxt is NULL when drwrap is unwinding an exception: there is no
     * post-call state to query, and the callback exists only so we can free
     * what pre allocated (drwrap.h L358-370). */
    if (wrapcxt != NULL && f != INVALID_FILE) {
        dr_fprintf(f, "R seq=%d T%u api=%s site=" PFX " rv=" PIFX, next_seq(),
                   (uint)dr_get_thread_id(drcontext), drtrace_api_names[ctx->api_idx],
                   ctx->site, (ptr_uint_t)drwrap_get_retval(wrapcxt));
        /* Re-read the argument pointers now the call has returned. This is what
         * captures out-parameters, where the value is written into a
         * caller-supplied buffer rather than returned: GetComputerNameA,
         * GetVolumeInformationW, GetUserNameW, RegQueryValueExA and
         * GlobalMemoryStatusEx all deliver their answer that way. Those answers
         * are environment facts that exist nowhere in the binary. */
        for (i = 0; i < num_args; i++)
            maybe_log_string(f, "o", i, ctx->args[i]);
        dr_fprintf(f, "\n");
        dr_flush_file(f);
    }
    dr_thread_free(drcontext, ctx, sizeof(*ctx));
}

static void
event_module_load(void *drcontext, const module_data_t *info, bool loaded)
{
    const char *name = dr_module_preferred_name(info);
    int i, wrapped = 0;

    dr_mutex_lock(module_lock);
    if (module_file != INVALID_FILE) {
        dr_fprintf(module_file, "M seq=%d base=" PFX " end=" PFX " name=", next_seq(),
                   info->start, info->end);
        if (name != NULL)
            emit_hex(module_file, (const byte *)name, strlen(name));
        dr_fprintf(module_file, "\n");
        dr_flush_file(module_file);
    }
    dr_mutex_unlock(module_lock);

    for (i = 0; i < DRTRACE_API_COUNT; i++) {
        app_pc towrap = (app_pc)dr_get_proc_address(info->handle, drtrace_api_names[i]);
        if (towrap == NULL)
            continue;
        /* Wrap EVERY distinct address exporting the name, not just the first.
         *
         * Several system DLLs export one name at *different* addresses, the
         * outer a forwarder that tail-jumps to the inner:
         * kernel32!GetNativeSystemInfo jmps into kernelbase!GetNativeSystemInfo.
         * Wrapping only the first module to export it leaves the other
         * unwrapped, and a sample that resolves the unwrapped one directly --
         * plausible for one dodging kernel32 hooks -- is then never seen.
         * Wrapping both closes that, at the cost of one application call firing
         * two pre-callbacks.
         *
         * Those duplicates are collapsed on the host rather than here. A jmp
         * pushes no return address, so both hops report the same call site,
         * which makes the pair look like two real calls to anything examining a
         * record in isolation -- but the second C arrives while the first is
         * still in flight on the thread, with no R between them, and two
         * genuine calls cannot do that. drtrace_parse keys on exactly that.
         *
         * drwrap_is_wrapped still guards the literal same-address case: drwrap
         * stacks a repeat request whose callback pair is identical rather than
         * rejecting it. */
        if (drwrap_is_wrapped(towrap, wrap_pre, wrap_post))
            continue;
        if (drwrap_wrap_ex(towrap, wrap_pre, wrap_post, (void *)(ptr_int_t)i,
                           DRWRAP_UNWIND_ON_EXCEPTION))
            wrapped++;
    }
    dr_log(NULL, DR_LOG_ALL, 1, "drtrace: module %s -> wrapped %d APIs\n",
           name == NULL ? "?" : name, wrapped);
}

/* -------------------------------------------------------------------------- */
/* lifecycle                                                                   */
/* -------------------------------------------------------------------------- */

static void
event_thread_init(void *drcontext)
{
    char path[MAXIMUM_PATH];
    file_t f;

    dr_snprintf(path, BUFFER_SIZE_ELEMENTS(path), "%s\\drtrace.%u.%u.log", logdir,
                (uint)dr_get_process_id(), (uint)dr_get_thread_id(drcontext));
    path[BUFFER_SIZE_ELEMENTS(path) - 1] = '\0';

    f = dr_open_file(path, DR_FILE_WRITE_OVERWRITE | DR_FILE_ALLOW_LARGE);
    if (f == INVALID_FILE) {
        /* Graceful degrade -- do NOT DR_ASSERT/dr_abort(): an unwritable logdir
         * would abort the analyzed process, and under CAPE that destroys the
         * whole analysis. Losing this thread's output is far cheaper. */
        dr_log(NULL, DR_LOG_ALL, 1,
               "drtrace: could not open per-thread log '%s'; this thread will not log\n",
               path);
        drmgr_set_tls_field(drcontext, tls_idx, (void *)(ptr_uint_t)f);
        return;
    }

    /* Widen through ptr_uint_t like the samples. Lossless only on the 32-bit
     * target: file_t fits in ptr_uint_t here. Correct for the PE32/x86 guest. */
    drmgr_set_tls_field(drcontext, tls_idx, (void *)(ptr_uint_t)f);

    dr_fprintf(f, "# drtrace v1 pid=%u tid=%u\n", (uint)dr_get_process_id(),
               (uint)dr_get_thread_id(drcontext));
    dr_flush_file(f);
}

static void
event_thread_exit(void *drcontext)
{
    file_t f = (file_t)(ptr_uint_t)drmgr_get_tls_field(drcontext, tls_idx);
    if (f != INVALID_FILE) {
        dr_flush_file(f);
        dr_close_file(f);
    }
}

static void
event_exit(void)
{
    if (module_file != INVALID_FILE) {
        dr_flush_file(module_file);
        dr_close_file(module_file);
    }
    dr_mutex_destroy(module_lock);
    dr_mutex_destroy(hitcap_lock);
    drmgr_unregister_tls_field(tls_idx);
    drwrap_exit();
    drmgr_exit();
}

/* Parse "<flag> <int>" if argv[*i] matches, advancing *i. Uses dr_sscanf rather
 * than strtol: a DR client runs without a usable libc. */
static bool
int_option(const char *flag, int argc, const char *argv[], int *i, int *out)
{
    int parsed = 0;
    if (strcmp(argv[*i], flag) != 0 || *i + 1 >= argc)
        return false;
    if (dr_sscanf(argv[*i + 1], "%d", &parsed) == 1)
        *out = parsed;
    (*i)++;
    return true;
}

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    char path[MAXIMUM_PATH];
    int i;

    dr_set_client_name("Clew Channel 3 API + comparison tracer 'drtrace'",
                       "http://dynamorio.org/issues");

    /* Manual option parse (kept in C; avoids the C++ droption dependency).
     * exe_drtrace.py invokes: -c drtrace.dll -logdir "<dir>" -- <sample> */
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-logdir") == 0 && i + 1 < argc) {
            dr_snprintf(logdir, BUFFER_SIZE_ELEMENTS(logdir), "%s", argv[i + 1]);
            logdir[BUFFER_SIZE_ELEMENTS(logdir) - 1] = '\0';
            i++;
        } else if (int_option("-nargs", argc, argv, &i, &num_args)) {
            if (num_args < 0)
                num_args = 0;
            if (num_args > DRTRACE_MAX_ARGS)
                num_args = DRTRACE_MAX_ARGS;
        } else if (int_option("-maxhits", argc, argv, &i, &max_hits)) {
            /* <=0 disables the cap */
        } else if (int_option("-minstr", argc, argv, &i, &min_str_chars)) {
            if (min_str_chars < 1)
                min_str_chars = 1;
        }
    }

    if (!drmgr_init())
        DR_ASSERT(false);
    if (!drwrap_init())
        DR_ASSERT(false);
    my_id = id;

    /* The stack we read arguments and return addresses off belongs to a sample
     * that may be actively hostile to instrumentation. Both reads default to
     * direct access; make them safe reads so an unmapped or trapped stack
     * degrades to a missing value instead of crashing the analysis. These are
     * global flags (drwrap_global_flags_t), not per-wrap ones. */
    drwrap_set_global_flags(DRWRAP_SAFE_READ_RETADDR | DRWRAP_SAFE_READ_ARGS);

    /* Best-effort: the CAPE package also makes this. dr_create_dir fails if it
     * already exists -- fine, ignore. */
    dr_create_dir(logdir);

    module_lock = dr_mutex_create();
    hitcap_lock = dr_mutex_create();

    /* One process-wide module table: module loads can arrive before a given
     * thread's TLS slot exists, and one copy of the table is all the host needs. */
    dr_snprintf(path, BUFFER_SIZE_ELEMENTS(path), "%s\\drtrace.%u.modules.log", logdir,
                (uint)dr_get_process_id());
    path[BUFFER_SIZE_ELEMENTS(path) - 1] = '\0';
    module_file = dr_open_file(path, DR_FILE_WRITE_OVERWRITE | DR_FILE_ALLOW_LARGE);
    if (module_file == INVALID_FILE) {
        dr_log(NULL, DR_LOG_ALL, 1, "drtrace: could not open module log '%s'\n", path);
    } else {
        dr_fprintf(module_file, "# drtrace v1 pid=%u modules\n", (uint)dr_get_process_id());
        dr_flush_file(module_file);
    }

    drmgr_register_exit_event(event_exit);
    if (!drmgr_register_thread_init_event(event_thread_init) ||
        !drmgr_register_thread_exit_event(event_thread_exit) ||
        !drmgr_register_module_load_event(event_module_load) ||
        !drmgr_register_bb_instrumentation_event(NULL /*analysis*/, event_app_instruction,
                                                 NULL))
        DR_ASSERT(false);

    tls_idx = drmgr_register_tls_field();
    DR_ASSERT(tls_idx > -1);

    dr_log(NULL, DR_LOG_ALL, 1,
           "Client 'drtrace' initializing; logdir=%s nargs=%d maxhits=%d minstr=%d\n", logdir,
           num_args, max_hits, min_str_chars);
}
