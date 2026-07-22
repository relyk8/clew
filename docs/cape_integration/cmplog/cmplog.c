/* ***************************************************************************
 * cmplog.c  --  Clew Channel 3: comparison-operand logging DynamoRIO client
 *
 * Built for DynamoRIO 11.91.20651, 32-bit (target guest is PE32 / x86).
 * FIRST DRAFT -- COMPILE-UNVERIFIED: there is no MSVC toolchain on the Linux
 * dev host; this must be built inside a Windows dev snapshot (see BUILD_RECIPE.md).
 * Every DR API call below was checked against the headers in
 *   /home/relyk8/dr-sdk/DynamoRIO-Windows-11.91.20651/include (+ ext/include)
 * and the shipped samples (instrcalls.c, memtrace_simple.c, utils.c).
 *
 * WHAT IT DOES
 *   For every executed OP_cmp / OP_test application instruction, it decodes the
 *   instruction at its app PC and logs the *runtime* value of each source
 *   operand (register -> live value, immediate -> constant, memory -> the bytes
 *   actually read). This surfaces the concrete value a sample's evasion check
 *   compares against (e.g. the "2GB" behind "if RAM < 2GB, hide").
 *
 * DESIGN (correctness-first, modeled on the DR samples)
 *   - Per-thread text log file, handle stashed in a drmgr TLS field.
 *   - Insertion event flags OP_cmp/OP_test app instrs and inserts a clean call
 *     to at_compare(), passing only the app PC; at_compare re-decodes at that PC
 *     and reads live operand state from the mcontext. (No inlined instrumentation
 *     -- slower but simple and robust for a first draft.)
 *   - We FLUSH after every logged record. This is REQUIRED: CAPE kills the
 *     target at the analysis timeout, so anything not already on disk is lost
 *     (the "drcov flush caveat" -- drcov only wrote on clean exit and produced
 *     0-byte logs under CAPE). Flushing per-record means a timeout-kill still
 *     leaves every comparison seen so far.
 *
 * FUTURE (documented, not implemented here)
 *   - Additional comparison-class opcodes: OP_sub (flag-setting subtract),
 *     the cmov* / set* families, OP_cmpxchg, string-compare (OP_cmps*),
 *     OP_bt* family, OP_ucomiss, etc. Start narrow (cmp/test) for signal-to-noise.
 *   - Inlined buffering (memtrace-style) instead of a per-cmp clean call, once
 *     the operand extraction is validated.
 * ***************************************************************************/

#include "dr_api.h"
#include "drmgr.h"
#include <string.h> /* strcmp */

/* element count of a fixed-size char buffer (utils.h defines this, but we don't
 * link utils.c -- keep cmplog.c self-contained). */
#define BUFFER_SIZE_ELEMENTS(buf) (sizeof(buf) / sizeof((buf)[0]))

/* ---- opcode set we instrument (start narrow; see FUTURE above) ---- */
static bool
is_compare_opcode(int opc)
{
    /* OP_cmp (dr_ir_opcodes_x86.h #14) and OP_test (#60) both set flags from a
     * comparison/AND and are the canonical evasion-check primitives. */
    return opc == OP_cmp || opc == OP_test;
}

/* Cap on bytes read + printed for a memory operand. Target is 32-bit, so
 * pointer-sized covers the common cmp operand widths (1/2/4). Wider SIMD
 * compares are out of scope for this draft. */
#define CMPLOG_MAX_MEM_BYTES sizeof(reg_t)

/* Default log directory inside the guest. The CAPE package (exe_cmplog.py)
 * also creates this, mirroring how exe_drcov makes C:\drcov_logs; we attempt
 * to create it here too so a manual drrun works standalone. Overridable via
 * the "-logdir <dir>" client option (parsed in dr_client_main). */
static char logdir[MAXIMUM_PATH] = "C:\\cmp_logs";

static int tls_idx;          /* drmgr TLS slot holding the per-thread file_t */
static client_id_t my_id;

/* -------------------------------------------------------------------------- */

static void
event_exit(void)
{
    drmgr_unregister_tls_field(tls_idx);
    drmgr_exit();
}

static void
event_thread_init(void *drcontext)
{
    char path[MAXIMUM_PATH];
    file_t f;
    /* Filename pattern: cmplog.<pid>.<tid>.log (one file per thread). */
    dr_snprintf(path, BUFFER_SIZE_ELEMENTS(path), "%s\\cmplog.%u.%u.log", logdir,
                (uint)dr_get_process_id(), (uint)dr_get_thread_id(drcontext));
    path[BUFFER_SIZE_ELEMENTS(path) - 1] = '\0';

    /* dr_open_file(const char *fname, uint mode_flags) -> file_t
     * (INVALID_FILE on failure). OVERWRITE so a re-run starts fresh. */
    f = dr_open_file(path, DR_FILE_WRITE_OVERWRITE | DR_FILE_ALLOW_LARGE);
    if (f == INVALID_FILE) {
        /* Graceful degrade -- do NOT DR_ASSERT/dr_abort() here: an unwritable
         * logdir would abort the analyzed sample process, and under the CAPE
         * sandbox that destroys the whole analysis (incl. CAPE's own API-call
         * log). Losing just this client's per-thread output is far cheaper.
         * Stash INVALID_FILE so the per-record path (at_compare) logs nothing. */
        dr_log(NULL, DR_LOG_ALL, 1,
               "cmplog: could not open per-thread log '%s'; this thread will not log\n",
               path);
        drmgr_set_tls_field(drcontext, tls_idx, (void *)(ptr_uint_t)f);
        return;
    }

    /* Store handle in the TLS slot (widen through ptr_uint_t like the samples).
     * Lossless only on the 32-bit target: file_t fits in ptr_uint_t here; this
     * round-trip (also at thread-exit / at_compare) would truncate if ever
     * built 64-bit. The casts are correct for the PE32/x86 guest. */
    drmgr_set_tls_field(drcontext, tls_idx, (void *)(ptr_uint_t)f);

    if (f != INVALID_FILE) {
        dr_fprintf(f, "# clew cmplog thread=%u pid=%u\n", (uint)dr_get_thread_id(drcontext),
                   (uint)dr_get_process_id());
        dr_fprintf(f, "# fields: T<tid> pc=<app_pc> <opcode> src[i]=<kind>:<hexval>...\n");
        dr_flush_file(f);
    }
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

/* Clean-call target: reconstruct the comparison at `pc` and log live operands.
 * Signature must match the arg we pass via dr_insert_clean_call (one pointer-
 * sized value). */
static void
at_compare(app_pc pc)
{
    void *drcontext = dr_get_current_drcontext();
    file_t f = (file_t)(ptr_uint_t)drmgr_get_tls_field(drcontext, tls_idx);
    dr_mcontext_t mc;
    /* reg_get_value / opnd_compute_address require DR_MC_CONTROL|DR_MC_INTEGER. */
    instr_noalloc_t noalloc; /* heap-free decode buffer (safe in a clean call) */
    instr_t *instr;
    int nsrcs, i, opc;

    if (f == INVALID_FILE)
        return;

    mc.size = sizeof(mc);
    mc.flags = DR_MC_CONTROL | DR_MC_INTEGER;
    if (!dr_get_mcontext(drcontext, &mc))
        return;

    /* decode(void *drcontext, byte *pc, instr_t *instr) -> byte* (next pc), NULL
     * on invalid. instr_noalloc avoids heap allocation. */
    instr_noalloc_init(drcontext, &noalloc);
    instr = instr_from_noalloc(&noalloc);
    if (decode(drcontext, pc, instr) == NULL)
        return;

    opc = instr_get_opcode(instr);
    dr_fprintf(f, "T%u pc=" PFX " %s", (uint)dr_get_thread_id(drcontext), pc,
               decode_opcode_name(opc));

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
            if (sz == 0 || sz > CMPLOG_MAX_MEM_BYTES)
                sz = (uint)CMPLOG_MAX_MEM_BYTES;
            /* dr_safe_read: no exception if the address is unmapped. */
            if (addr != NULL && dr_safe_read(addr, sz, &val, &got) && got > 0) {
                dr_fprintf(f, " src%d=mem[" PFX "]=" PIFX, i, addr, (ptr_uint_t)val);
            } else {
                dr_fprintf(f, " src%d=mem[" PFX "]=<unreadable>", i, addr);
            }
        } else {
            /* pc-relative, far, float/SIMD, etc. -- out of scope for the draft. */
            dr_fprintf(f, " src%d=other", i);
        }
    }
    dr_fprintf(f, "\n");
    /* REQUIRED: survive the CAPE timeout-kill (see flush caveat at top). */
    dr_flush_file(f);
}

/* drmgr insertion-stage callback (analysis_func was NULL at registration). */
static dr_emit_flags_t
event_app_instruction(void *drcontext, void *tag, instrlist_t *bb, instr_t *instr,
                      bool for_trace, bool translating, void *user_data)
{
    int opc;
    /* Only instrument real application instructions (skip DR/other-client meta,
     * and the label/emulation markers drmgr can insert). */
    if (!instr_is_app(instr))
        return DR_EMIT_DEFAULT;

    opc = instr_get_opcode(instr);
    if (is_compare_opcode(opc)) {
        app_pc pc = instr_get_app_pc(instr);
        if (pc != NULL) {
            /* dr_insert_clean_call(drcontext, ilist, where, callee, save_fpstate,
             *                      num_args, ...);  each vararg is an opnd_t.
             * Pass the app PC as a pointer-sized immediate; at_compare re-decodes
             * there and reads the live mcontext.
             * NOTE: plain dr_insert_clean_call stores app state on the DR stack for
             * dr_get_mcontext(). The DR_CLEANCALL_READS_APP_CONTEXT flag (via the _ex
             * form) is only required when drreg register reservation is in use --
             * cmplog uses neither drreg nor any inlined reg spills, so this is correct. */
            dr_insert_clean_call(drcontext, bb, instr, (void *)at_compare,
                                 false /*no fpstate*/, 1, OPND_CREATE_INTPTR((ptr_int_t)pc));
        }
    }
    return DR_EMIT_DEFAULT;
}

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    int i;
    dr_set_client_name("Clew Channel 3 comparison-operand logger 'cmplog'",
                       "http://dynamorio.org/issues");

    /* Manual option parse (kept in C; avoids the C++ droption dependency).
     * exe_cmplog.py invokes: -c cmplog.dll -logdir "<dir>" -- <sample> */
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-logdir") == 0 && i + 1 < argc) {
            dr_snprintf(logdir, BUFFER_SIZE_ELEMENTS(logdir), "%s", argv[i + 1]);
            logdir[BUFFER_SIZE_ELEMENTS(logdir) - 1] = '\0';
            i++;
        }
    }

    if (!drmgr_init())
        DR_ASSERT(false);
    my_id = id;

    /* Best-effort: ensure the log dir exists (the CAPE package also makes it).
     * dr_create_dir fails if it already exists -- that's fine, ignore. */
    dr_create_dir(logdir);

    drmgr_register_exit_event(event_exit);
    if (!drmgr_register_thread_init_event(event_thread_init) ||
        !drmgr_register_thread_exit_event(event_thread_exit) ||
        !drmgr_register_bb_instrumentation_event(NULL /*analysis*/, event_app_instruction,
                                                 NULL))
        DR_ASSERT(false);

    tls_idx = drmgr_register_tls_field();
    DR_ASSERT(tls_idx > -1);

    dr_log(NULL, DR_LOG_ALL, 1, "Client 'cmplog' initializing; logdir=%s\n", logdir);
}
