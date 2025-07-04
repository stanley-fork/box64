#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <math.h>
#include <signal.h>
#include <sys/types.h>
#include <unistd.h>

#include "debug.h"
#include "box64context.h"
#include "box64cpu.h"
#include "emu/x64emu_private.h"
#include "x64emu.h"
#include "box64stack.h"
#include "callback.h"
#include "emu/x64run_private.h"
#include "emu/x87emu_private.h"
#include "x64trace.h"
#include "signals.h"
#include "dynarec_native.h"
#include "dynarec_la64_private.h"
#include "dynarec_la64_functions.h"
#include "custommem.h"
#include "bridge.h"
#include "gdbjit.h"
#include "perfmap.h"
#include "elfloader.h"

#define XMM0 0
#define X870 16
#define EMM0 16

// Get a FPU scratch reg
int fpu_get_scratch(dynarec_la64_t* dyn)
{
    return SCRATCH0 + dyn->lsx.fpu_scratch++; // return an Sx
}
// Reset scratch regs counter
void fpu_reset_scratch(dynarec_la64_t* dyn)
{
    dyn->lsx.fpu_scratch = 0;
}

// Free a FPU double reg
void fpu_free_reg(dynarec_la64_t* dyn, int reg)
{
    // TODO: check upper limit?
    dyn->lsx.fpuused[reg] = 0;
    if (dyn->lsx.lsxcache[reg].t != LSX_CACHE_ST_F && dyn->lsx.lsxcache[reg].t != LSX_CACHE_ST_D && dyn->lsx.lsxcache[reg].t != LSX_CACHE_ST_I64)
        dyn->lsx.lsxcache[reg].v = 0;
}
// Get an MMX double reg
int fpu_get_reg_emm(dynarec_la64_t* dyn, int emm)
{
    int ret = EMM0 + emm;
    dyn->lsx.fpuused[ret] = 1;
    dyn->lsx.lsxcache[ret].t = LSX_CACHE_MM;
    dyn->lsx.lsxcache[ret].n = emm;
    dyn->lsx.news |= (1 << (ret));
    return ret;
}
// Get an XMM quad reg
int fpu_get_reg_xmm(dynarec_la64_t* dyn, int t, int xmm)
{
    int i;
    i = XMM0 + xmm;

    dyn->lsx.fpuused[i] = 1;
    dyn->lsx.lsxcache[i].t = t;
    dyn->lsx.lsxcache[i].n = xmm;
    dyn->lsx.news |= (1 << i);
    return i;
}

// Get an YMM quad reg
int fpu_get_reg_ymm(dynarec_la64_t* dyn, int t, int ymm)
{
    int i;
    i = XMM0 + ymm;

    dyn->lsx.fpuused[i] = 1;
    dyn->lsx.lsxcache[i].t = t;
    dyn->lsx.lsxcache[i].n = ymm;
    dyn->lsx.news |= (1 << i);
    return i;
}

// Reset fpu regs counter
static void fpu_reset_reg_lsxcache(lsxcache_t* lsx)
{
    for (int i = 0; i < 24; ++i) {
        lsx->fpuused[i] = 0;
        lsx->lsxcache[i].v = 0;
    }
}

void fpu_reset_reg(dynarec_la64_t* dyn)
{
    fpu_reset_reg_lsxcache(&dyn->lsx);
}

static int isCacheEmpty(dynarec_native_t* dyn, int ninst)
{
    if (dyn->insts[ninst].lsx.stack_next) {
        return 0;
    }
    for (int i = 0; i < 24; ++i)
        if (dyn->insts[ninst].lsx.lsxcache[i].v) { // there is something at ninst for i
            if (!(
                    (dyn->insts[ninst].lsx.lsxcache[i].t == LSX_CACHE_ST_F
                        || dyn->insts[ninst].lsx.lsxcache[i].t == LSX_CACHE_ST_D
                        || dyn->insts[ninst].lsx.lsxcache[i].t == LSX_CACHE_ST_I64)
                    && dyn->insts[ninst].lsx.lsxcache[i].n < dyn->insts[ninst].lsx.stack_pop))
                return 0;
        }
    return 1;
}

int fpuCacheNeedsTransform(dynarec_la64_t* dyn, int ninst)
{
    int i2 = dyn->insts[ninst].x64.jmp_insts;
    if (i2 < 0)
        return 1;
    if ((dyn->insts[i2].x64.barrier & BARRIER_FLOAT))
        // if the barrier as already been apply, no transform needed
        return ((dyn->insts[ninst].x64.barrier & BARRIER_FLOAT)) ? 0 : (isCacheEmpty(dyn, ninst) ? 0 : 1);
    int ret = 0;
    if (!i2) { // just purge
        if (dyn->insts[ninst].lsx.stack_next) {
            return 1;
        }
        for (int i = 0; i < 24 && !ret; ++i)
            if (dyn->insts[ninst].lsx.lsxcache[i].v) { // there is something at ninst for i
                if (!(
                        (dyn->insts[ninst].lsx.lsxcache[i].t == LSX_CACHE_ST_F
                            || dyn->insts[ninst].lsx.lsxcache[i].t == LSX_CACHE_ST_D
                            || dyn->insts[ninst].lsx.lsxcache[i].t == LSX_CACHE_ST_I64)
                        && dyn->insts[ninst].lsx.lsxcache[i].n < dyn->insts[ninst].lsx.stack_pop))
                    ret = 1;
            }
        return ret;
    }
    // Check if ninst can be compatible to i2
    if (dyn->insts[ninst].lsx.stack_next != dyn->insts[i2].lsx.stack - dyn->insts[i2].lsx.stack_push) {
        return 1;
    }
    lsxcache_t cache_i2 = dyn->insts[i2].lsx;
    lsxcacheUnwind(&cache_i2);

    for (int i = 0; i < 24; ++i) {
        if (dyn->insts[ninst].lsx.lsxcache[i].v) { // there is something at ninst for i
            if (!cache_i2.lsxcache[i].v) {         // but there is nothing at i2 for i
                ret = 1;
            } else if (dyn->insts[ninst].lsx.lsxcache[i].v != cache_i2.lsxcache[i].v) { // there is something different
                if (dyn->insts[ninst].lsx.lsxcache[i].n != cache_i2.lsxcache[i].n) {    // not the same x64 reg
                    ret = 1;
                } else if (dyn->insts[ninst].lsx.lsxcache[i].t == LSX_CACHE_XMMR && cache_i2.lsxcache[i].t == LSX_CACHE_XMMW) { /* nothing */
                } else if (dyn->insts[ninst].lsx.lsxcache[i].t == LSX_CACHE_YMMR && cache_i2.lsxcache[i].t == LSX_CACHE_YMMW) { /* nothing */
                } else
                    ret = 1;
            }
        } else if (cache_i2.lsxcache[i].v)
            ret = 1;
    }
    return ret;
}

void lsxcacheUnwind(lsxcache_t* cache)
{
    if (cache->swapped) {
        // unswap
        int a = -1;
        int b = -1;
        for (int j = 0; j < 24 && ((a == -1) || (b == -1)); ++j)
            if ((cache->lsxcache[j].t == LSX_CACHE_ST_D || cache->lsxcache[j].t == LSX_CACHE_ST_F || cache->lsxcache[j].t == LSX_CACHE_ST_I64)) {
                if (cache->lsxcache[j].n == cache->combined1)
                    a = j;
                else if (cache->lsxcache[j].n == cache->combined2)
                    b = j;
            }
        if (a != -1 && b != -1) {
            int tmp = cache->lsxcache[a].n;
            cache->lsxcache[a].n = cache->lsxcache[b].n;
            cache->lsxcache[b].n = tmp;
        }
        cache->swapped = 0;
        cache->combined1 = cache->combined2 = 0;
    }
    if (cache->news) {
        // reove the newly created lsxcache
        for (int i = 0; i < 24; ++i)
            if (cache->news & (1 << i))
                cache->lsxcache[i].v = 0;
        cache->news = 0;
    }
    if (cache->stack_push) {
        // unpush
        for (int j = 0; j < 24; ++j) {
            if ((cache->lsxcache[j].t == LSX_CACHE_ST_D || cache->lsxcache[j].t == LSX_CACHE_ST_F || cache->lsxcache[j].t == LSX_CACHE_ST_I64)) {
                if (cache->lsxcache[j].n < cache->stack_push)
                    cache->lsxcache[j].v = 0;
                else
                    cache->lsxcache[j].n -= cache->stack_push;
            }
        }
        cache->x87stack -= cache->stack_push;
        cache->tags >>= (cache->stack_push * 2);
        cache->stack -= cache->stack_push;
        if (cache->pushed >= cache->stack_push)
            cache->pushed -= cache->stack_push;
        else
            cache->pushed = 0;
        cache->stack_push = 0;
    }
    cache->x87stack += cache->stack_pop;
    cache->stack_next = cache->stack;
    if (cache->stack_pop) {
        if (cache->poped >= cache->stack_pop)
            cache->poped -= cache->stack_pop;
        else
            cache->poped = 0;
        cache->tags <<= (cache->stack_pop * 2);
    }
    cache->stack_pop = 0;
    cache->barrier = 0;
    // And now, rebuild the x87cache info with lsxcache
    cache->mmxcount = 0;
    cache->fpu_scratch = 0;
    for (int i = 0; i < 8; ++i) {
        cache->x87cache[i] = -1;
        cache->mmxcache[i] = -1;
        cache->x87reg[i] = 0;
        cache->ssecache[i * 2].v = -1;
        cache->ssecache[i * 2 + 1].v = -1;
        cache->avxcache[i * 2].v = -1;
        cache->avxcache[i * 2 + 1].v = -1;
    }
    int x87reg = 0;
    for (int i = 0; i < 24; ++i) {
        if (cache->lsxcache[i].v) {
            cache->fpuused[i] = 1;
            switch (cache->lsxcache[i].t) {
                case LSX_CACHE_MM:
                    cache->mmxcache[cache->lsxcache[i].n] = i;
                    ++cache->mmxcount;
                    break;
                case LSX_CACHE_XMMR:
                case LSX_CACHE_XMMW:
                    cache->ssecache[cache->lsxcache[i].n].reg = i;
                    cache->ssecache[cache->lsxcache[i].n].write = (cache->lsxcache[i].t == LSX_CACHE_XMMW) ? 1 : 0;
                    break;
                case LSX_CACHE_YMMR:
                case LSX_CACHE_YMMW:
                    cache->avxcache[cache->lsxcache[i].n].reg = i;
                    cache->avxcache[cache->lsxcache[i].n].write = (cache->lsxcache[i].t == LSX_CACHE_YMMW) ? 1 : 0;
                    break;
                case LSX_CACHE_ST_F:
                case LSX_CACHE_ST_D:
                case LSX_CACHE_ST_I64:
                    cache->x87cache[x87reg] = cache->lsxcache[i].n;
                    cache->x87reg[x87reg] = i;
                    ++x87reg;
                    break;
                case LSX_CACHE_SCR:
                    cache->fpuused[i] = 0;
                    cache->lsxcache[i].v = 0;
                    break;
            }
        } else {
            cache->fpuused[i] = 0;
        }
    }
}

const char* getCacheName(int t, int n)
{
    static char buff[20];
    switch (t) {
        case LSX_CACHE_ST_D: sprintf(buff, "ST%d", n); break;
        case LSX_CACHE_ST_F: sprintf(buff, "st%d", n); break;
        case LSX_CACHE_ST_I64: sprintf(buff, "STi%d", n); break;
        case LSX_CACHE_MM: sprintf(buff, "MM%d", n); break;
        case LSX_CACHE_XMMW: sprintf(buff, "XMM%d", n); break;
        case LSX_CACHE_XMMR: sprintf(buff, "xmm%d", n); break;
        case LSX_CACHE_YMMW: sprintf(buff, "YMM%d", n); break;
        case LSX_CACHE_YMMR: sprintf(buff, "ymm%d", n); break;        
        case LSX_CACHE_SCR: sprintf(buff, "Scratch"); break;
        case LSX_CACHE_NONE: buff[0] = '\0'; break;
    }
    return buff;
}

static register_mapping_t register_mappings[] = {
    { "rax", "t0" },
    { "eax", "t0" },
    { "ax", "t0" },
    { "ah", "t0" },
    { "al", "t0" },
    { "rcx", "t1" },
    { "ecx", "t1" },
    { "cx", "t1" },
    { "ch", "t1" },
    { "cl", "t1" },
    { "rdx", "t2" },
    { "edx", "t2" },
    { "dx", "t2" },
    { "dh", "t2" },
    { "dl", "t2" },
    { "rbx", "t3" },
    { "ebx", "t3" },
    { "bx", "t3" },
    { "bh", "t3" },
    { "bl", "t3" },
    { "rsi", "t4" },
    { "esi", "t4" },
    { "si", "t4" },
    { "sil", "t4" },
    { "rdi", "t5" },
    { "edi", "t5" },
    { "di", "t5" },
    { "dil", "t5" },
    { "rsp", "t6" },
    { "esp", "t6" },
    { "sp", "t6" },
    { "spl", "t6" },
    { "rbp", "t7" },
    { "ebp", "t7" },
    { "bp", "t7" },
    { "bpl", "t7" },
    { "r8", "s0" },
    { "r8d", "s0" },
    { "r8w", "s0" },
    { "r8b", "s0" },
    { "r9", "s1" },
    { "r9d", "s1" },
    { "r9w", "s1" },
    { "r9b", "s1" },
    { "r10", "s2" },
    { "r10d", "s2" },
    { "r10w", "s2" },
    { "r10b", "s2" },
    { "r11", "s3" },
    { "r11d", "s3" },
    { "r11w", "s3" },
    { "r11b", "s3" },
    { "r12", "s4" },
    { "r12d", "s4" },
    { "r12w", "s4" },
    { "r12b", "s4" },
    { "r13", "s5" },
    { "r13d", "s5" },
    { "r13w", "s5" },
    { "r13b", "s5" },
    { "r14", "s6" },
    { "r14d", "s6" },
    { "r14w", "s6" },
    { "r14b", "s6" },
    { "r15", "s7" },
    { "r15d", "s7" },
    { "r15w", "s7" },
    { "r15b", "s7" },
    { "rip", "t8" },
};

void printf_x64_instruction(dynarec_native_t* dyn, zydis_dec_t* dec, instruction_x64_t* inst, const char* name);
void inst_name_pass3(dynarec_native_t* dyn, int ninst, const char* name, rex_t rex)
{
    if (!dyn->need_dump && !BOX64ENV(dynarec_gdbjit) && !BOX64ENV(dynarec_perf_map)) return;

    static char buf[4096];
    int length = sprintf(buf, "barrier=%d state=%d/%d(%d), %s=%X/%X, use=%X, need=%X/%X, fuse=%d, sm=%d(%d/%d)",
        dyn->insts[ninst].x64.barrier,
        dyn->insts[ninst].x64.state_flags,
        dyn->f.pending,
        dyn->f.dfnone,
        dyn->insts[ninst].x64.may_set ? "may" : "set",
        dyn->insts[ninst].x64.set_flags,
        dyn->insts[ninst].x64.gen_flags,
        dyn->insts[ninst].x64.use_flags,
        dyn->insts[ninst].x64.need_before,
        dyn->insts[ninst].x64.need_after,
        dyn->insts[ninst].nat_flags_fusion,
        dyn->smwrite, dyn->insts[ninst].will_write, dyn->insts[ninst].last_write);
    if (dyn->insts[ninst].pred_sz) {
        length += sprintf(buf + length, ", pred=");
        for (int ii = 0; ii < dyn->insts[ninst].pred_sz; ++ii)
            length += sprintf(buf + length, "%s%d", ii ? "/" : "", dyn->insts[ninst].pred[ii]);
    }
    if (dyn->insts[ninst].x64.jmp && dyn->insts[ninst].x64.jmp_insts >= 0)
        length += sprintf(buf + length, ", jmp=%d", dyn->insts[ninst].x64.jmp_insts);
    if (dyn->insts[ninst].x64.jmp && dyn->insts[ninst].x64.jmp_insts == -1)
        length += sprintf(buf + length, ", jmp=out");
    if (dyn->last_ip)
        length += sprintf(buf + length, ", last_ip=%p", (void*)dyn->last_ip);
    for (int ii = 0; ii < 24; ++ii) {
        switch (dyn->insts[ninst].lsx.lsxcache[ii].t) {
            case LSX_CACHE_ST_D: length += sprintf(buf + length, " D%d:%s", ii, getCacheName(dyn->insts[ninst].lsx.lsxcache[ii].t, dyn->insts[ninst].lsx.lsxcache[ii].n)); break;
            case LSX_CACHE_ST_F: length += sprintf(buf + length, " S%d:%s", ii, getCacheName(dyn->insts[ninst].lsx.lsxcache[ii].t, dyn->insts[ninst].lsx.lsxcache[ii].n)); break;
            case LSX_CACHE_ST_I64: length += sprintf(buf + length, " D%d:%s", ii, getCacheName(dyn->insts[ninst].lsx.lsxcache[ii].t, dyn->insts[ninst].lsx.lsxcache[ii].n)); break;
            case LSX_CACHE_MM: length += sprintf(buf + length, " D%d:%s", ii, getCacheName(dyn->insts[ninst].lsx.lsxcache[ii].t, dyn->insts[ninst].lsx.lsxcache[ii].n)); break;
            case LSX_CACHE_XMMW: length += sprintf(buf + length, " Q%d:%s", ii, getCacheName(dyn->insts[ninst].lsx.lsxcache[ii].t, dyn->insts[ninst].lsx.lsxcache[ii].n)); break;
            case LSX_CACHE_XMMR: length += sprintf(buf + length, " Q%d:%s", ii, getCacheName(dyn->insts[ninst].lsx.lsxcache[ii].t, dyn->insts[ninst].lsx.lsxcache[ii].n)); break;
            case LSX_CACHE_YMMW: length += sprintf(buf + length, " Q%d:%s%s", ii, getCacheName(dyn->insts[ninst].lsx.lsxcache[ii].t, dyn->insts[ninst].lsx.lsxcache[ii].n), dyn->insts[ninst].lsx.avxcache[dyn->insts[ninst].lsx.lsxcache[ii].n].zero_upper==1?"-UZ":""); break;
            case LSX_CACHE_YMMR: length += sprintf(buf + length, " Q%d:%s%s", ii, getCacheName(dyn->insts[ninst].lsx.lsxcache[ii].t, dyn->insts[ninst].lsx.lsxcache[ii].n), dyn->insts[ninst].lsx.avxcache[dyn->insts[ninst].lsx.lsxcache[ii].n].zero_upper==1?"-UZ":""); break;
            case LSX_CACHE_SCR: length += sprintf(buf + length, " D%d:%s", ii, getCacheName(dyn->insts[ninst].lsx.lsxcache[ii].t, dyn->insts[ninst].lsx.lsxcache[ii].n)); break;
            case LSX_CACHE_NONE:
            default: break;
        }
    }
    if (dyn->lsx.stack || dyn->insts[ninst].lsx.stack_next || dyn->insts[ninst].lsx.x87stack)
        length += sprintf(buf + length, " X87:%d/%d(+%d/-%d)%d", dyn->lsx.stack, dyn->insts[ninst].lsx.stack_next, dyn->insts[ninst].lsx.stack_push, dyn->insts[ninst].lsx.stack_pop, dyn->insts[ninst].lsx.x87stack);
    if (dyn->insts[ninst].lsx.combined1 || dyn->insts[ninst].lsx.combined2)
        length += sprintf(buf + length, " %s:%d/%d", dyn->insts[ninst].lsx.swapped ? "SWP" : "CMB", dyn->insts[ninst].lsx.combined1, dyn->insts[ninst].lsx.combined2);

    if (dyn->need_dump) {
        printf_x64_instruction(dyn, rex.is32bits ? my_context->dec32 : my_context->dec, &dyn->insts[ninst].x64, name);
        dynarec_log(LOG_NONE, "%s%p: %d emitted opcodes, inst=%d, %s%s\n",
            (dyn->need_dump > 1) ? "\e[32m" : "",
            (void*)(dyn->native_start + dyn->insts[ninst].address), dyn->insts[ninst].size / 4, ninst, buf, (dyn->need_dump > 1) ? "\e[m" : "");
    }
    if (BOX64ENV(dynarec_gdbjit)) {
        static char buf2[512];
        if (BOX64ENV(dynarec_gdbjit) > 1) {
            sprintf(buf2, "; %d: %d opcodes, %s", ninst, dyn->insts[ninst].size / 4, buf);
            dyn->gdbjit_block = GdbJITBlockAddLine(dyn->gdbjit_block, (dyn->native_start + dyn->insts[ninst].address), buf2);
        }
        zydis_dec_t* dec = rex.is32bits ? my_context->dec32 : my_context->dec;
        const char* inst_name = name;
        if (dec) {
            inst_name = DecodeX64Trace(dec, dyn->insts[ninst].x64.addr, 0);
            x64disas_add_register_mapping_annotations(buf2, inst_name, register_mappings, sizeof(register_mappings) / sizeof(register_mappings[0]));
            inst_name = buf2;
        }
        dyn->gdbjit_block = GdbJITBlockAddLine(dyn->gdbjit_block, (dyn->native_start + dyn->insts[ninst].address), inst_name);
    }
    if (BOX64ENV(dynarec_perf_map) && BOX64ENV(dynarec_perf_map_fd) != -1) {
        writePerfMap(dyn->insts[ninst].x64.addr, dyn->native_start + dyn->insts[ninst].address, dyn->insts[ninst].size / 4, name);
    }
    if (length > sizeof(buf)) printf_log(LOG_NONE, "Warning: buf to small in inst_name_pass3 (%d vs %zd)\n", length, sizeof(buf));
}

// will go badly if address is unaligned
static uint8_t extract_byte(uint32_t val, void* address)
{
    int idx = (((uintptr_t)address) & 3) * 8;
    return (val >> idx) & 0xff;
}

static uint32_t insert_byte(uint32_t val, uint8_t b, void* address)
{
    int idx = (((uintptr_t)address) & 3) * 8;
    val &= ~(0xff << idx);
    val |= (((uint32_t)b) << idx);
    return val;
}

static uint16_t extract_half(uint32_t val, void* address)
{
    int idx = (((uintptr_t)address) & 3) * 8;
    return (val >> idx) & 0xffff;
}

static uint32_t insert_half(uint32_t val, uint16_t h, void* address)
{
    int idx = (((uintptr_t)address) & 3) * 8;
    val &= ~(0xffff << idx);
    val |= (((uint32_t)h) << idx);
    return val;
}

uint8_t la64_lock_xchg_b_slow(void* addr, uint8_t val)
{
    uint32_t ret;
    uint32_t* aligned = (uint32_t*)(((uintptr_t)addr) & ~3);
    do {
        ret = *aligned;
    } while (la64_lock_cas_d(aligned, ret, insert_byte(ret, val, addr)));
    return extract_byte(ret, addr);
}

int la64_lock_cas_b_slow(void* addr, uint8_t ref, uint8_t val)
{
    uint32_t* aligned = (uint32_t*)(((uintptr_t)addr) & ~3);
    uint32_t tmp = *aligned;
    return la64_lock_cas_d(aligned, insert_byte(tmp, ref, addr), insert_byte(tmp, val, addr));
}

int la64_lock_cas_h_slow(void* addr, uint16_t ref, uint16_t val)
{
    uint32_t* aligned = (uint32_t*)(((uintptr_t)addr) & ~3);
    uint32_t tmp = *aligned;
    return la64_lock_cas_d(aligned, insert_half(tmp, ref, addr), insert_half(tmp, val, addr));
}

void print_opcode(dynarec_native_t* dyn, int ninst, uint32_t opcode)
{
    dynarec_log_prefix(0, LOG_NONE, "\t%08x\t%s\n", opcode, la64_print(opcode, (uintptr_t)dyn->block));
}

static void x87_reset(lsxcache_t* lsx)
{
    for (int i = 0; i < 8; ++i)
        lsx->x87cache[i] = -1;
    lsx->tags = 0;
    lsx->x87stack = 0;
    lsx->stack = 0;
    lsx->stack_next = 0;
    lsx->stack_pop = 0;
    lsx->stack_push = 0;
    lsx->combined1 = lsx->combined2 = 0;
    lsx->swapped = 0;
    lsx->barrier = 0;
    lsx->pushed = 0;
    lsx->poped = 0;

    for (int i = 0; i < 24; ++i)
        if (lsx->lsxcache[i].t == LSX_CACHE_ST_F
            || lsx->lsxcache[i].t == LSX_CACHE_ST_D
            || lsx->lsxcache[i].t == LSX_CACHE_ST_I64)
            lsx->lsxcache[i].v = 0;
}

static void mmx_reset(lsxcache_t* lsx)
{
    lsx->mmxcount = 0;
    for (int i = 0; i < 8; ++i)
        lsx->mmxcache[i] = -1;
}

static void sse_reset(lsxcache_t* lsx)
{
    for (int i = 0; i < 16; ++i)
        lsx->ssecache[i].v = -1;
}
static void avx_reset(lsxcache_t* lsx)
{
    for (int i = 0; i < 16; ++i)
        lsx->avxcache[i].v = -1;
}

void fpu_reset(dynarec_la64_t* dyn)
{
    x87_reset(&dyn->lsx);
    mmx_reset(&dyn->lsx);
    sse_reset(&dyn->lsx);
    avx_reset(&dyn->lsx);
    fpu_reset_reg(dyn);
}

void fpu_reset_ninst(dynarec_la64_t* dyn, int ninst)
{
    // TODO: x87 and mmx
    sse_reset(&dyn->insts[ninst].lsx);
    avx_reset(&dyn->insts[ninst].lsx);
    fpu_reset_reg_lsxcache(&dyn->insts[ninst].lsx);
}

void fpu_save_and_unwind(dynarec_la64_t* dyn, int ninst, lsxcache_t* cache)
{
    memcpy(cache, &dyn->insts[ninst].lsx, sizeof(lsxcache_t));
    lsxcacheUnwind(&dyn->insts[ninst].lsx);
}
void fpu_unwind_restore(dynarec_la64_t* dyn, int ninst, lsxcache_t* cache)
{
    memcpy(&dyn->insts[ninst].lsx, cache, sizeof(lsxcache_t));
}

void updateNativeFlags(dynarec_la64_t* dyn)
{
    if (!BOX64ENV(dynarec_nativeflags))
        return;
    for (int i = 1; i < dyn->size; ++i)
        if (dyn->insts[i].nat_flags_fusion) {
            if (dyn->insts[i].pred_sz == 1 && dyn->insts[i].pred[0] == i - 1
                && (dyn->insts[i].x64.use_flags & dyn->insts[i - 1].x64.set_flags) == dyn->insts[i].x64.use_flags) {
                dyn->insts[i - 1].nat_flags_fusion = 1;
                if (dyn->insts[i].x64.use_flags & X_SF) {
                    dyn->insts[i - 1].nat_flags_needsign = 1;
                }
                dyn->insts[i].x64.use_flags = 0;
            } else
                dyn->insts[i].nat_flags_fusion = 0;
        }
}

void get_free_scratch(dynarec_la64_t* dyn, int ninst, uint8_t* tmp1, uint8_t* tmp2, uint8_t* tmp3, uint8_t s1, uint8_t s2, uint8_t s3, uint8_t s4, uint8_t s5)
{
    uint8_t n1 = dyn->insts[ninst].nat_flags_op1;
    uint8_t n2 = dyn->insts[ninst].nat_flags_op2;
    uint8_t tmp[5] = { 0 };
    int idx = 0;
#define GO(s) \
    if ((s != n1) && (s != n2)) tmp[idx++] = s
    GO(s1);
    GO(s2);
    GO(s3);
    GO(s4);
    GO(s5);
#undef GO
    *tmp1 = tmp[0];
    *tmp2 = tmp[1];
    *tmp3 = tmp[2];
}
