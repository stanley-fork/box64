#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <errno.h>

#include "debug.h"
#include "env.h"
#include "box64context.h"
#include "box64cpu.h"
#include "emu/x64emu_private.h"
#include "x64emu.h"
#include "box64stack.h"
#include "callback.h"
#include "emu/x64run_private.h"
#include "x64trace.h"
#include "dynarec_native.h"

#include "la64_printer.h"
#include "dynarec_la64_private.h"
#include "dynarec_la64_functions.h"
#include "../dynarec_helper.h"

uintptr_t dynarec64_AVX_F2_0F(dynarec_la64_t* dyn, uintptr_t addr, uintptr_t ip, int ninst, vex_t vex, int* ok, int* need_epilog)
{
    (void)ip;
    (void)need_epilog;

    uint8_t opcode = F8;
    uint8_t nextop, u8;
    uint8_t gd, ed, vd;
    uint8_t wback, wb1, wb2;
    uint8_t eb1, eb2, gb1, gb2;
    int32_t i32, i32_;
    int cacheupd = 0;
    int v0, v1, v2;
    int q0, q1, q2;
    int d0, d1, d2;
    int s0;
    uint64_t tmp64u, u64;
    int64_t j64;
    int64_t fixedaddress;
    int unscaled;
    MAYUSE(wb1);
    MAYUSE(wb2);
    MAYUSE(eb1);
    MAYUSE(eb2);
    MAYUSE(gb1);
    MAYUSE(gb2);
    MAYUSE(q0);
    MAYUSE(q1);
    MAYUSE(d0);
    MAYUSE(d1);
    MAYUSE(s0);
    MAYUSE(j64);
    MAYUSE(cacheupd);

    rex_t rex = vex.rex;

    switch (opcode) {

        case 0x10:
            INST_NAME("VMOVSD Gx, [Vx,] Ex");
            nextop = F8;
            if (MODREG) {
                GETVYx(q1, 0);
                GETEYSD(q2, 0, 0);
                GETGYx_empty(q0);
                if (gd != vex.v) VOR_V(q0, q1, q1);
                VEXTRINS_D(q0, q2, 0);
            } else {
                GETEYSD(q2, 0, 0);
                GETGYx_empty(q0);
                XVPICKVE_D(q0, q2, 0);
                YMM_UNMARK_UPPER_ZERO(q0);
            }
            break;
        case 0x11:
            INST_NAME("VMOVSD Ex, [Vx,] Gx");
            nextop = F8;
            GETGYx(q2, 0);
            if (MODREG) {
                if (ed == vex.v) {
                    GETEYSD(q0, 1, 0);
                    VEXTRINS_D(q0, q2, 0);
                } else {
                    GETVYx(q1, 0);
                    GETEYSD(q0, 1, 0);
                    VOR_V(q0, q1, q1);
                    VEXTRINS_D(q0, q2, 0);
                }
            } else {
                addr = geted(dyn, addr, ninst, nextop, &ed, x2, x1, &fixedaddress, rex, NULL, 1, 0);
                FST_D(q2, ed, fixedaddress);
                SMWRITE2();
            }
            break;
        case 0x12:
            INST_NAME("VMOVDDUP Gx, Ex");
            nextop = F8;
            if (MODREG) {
                GETGY_empty_EY_xy(q0, q1, 0);
            } else {
                GETGYxy_empty(q0);
                q1 = fpu_get_scratch(dyn);
                SMREAD();
                addr = geted(dyn, addr, ninst, nextop, &ed, x4, x5, &fixedaddress, rex, NULL, 0, 0);
                if (vex.l) {
                    XVLD(q1, ed, 0);
                } else {
                    VLDREPL_D(q0, ed, 0);
                }
            }
            if (vex.l) {
                XVSHUF4I_D(q0, q1, 0b1010);
            } else if (MODREG) {
                VREPLVE_D(q0, q1, 0);
            }
            break;
        case 0x58:
            INST_NAME("VADDSD Gx, Vx, Ex");
            nextop = F8;
            GETVYx(v1, 0);
            GETEYSD(v2, 0, 0);
            GETGYx_empty(v0);
            d0 = fpu_get_scratch(dyn);
            FADD_D(d0, v1, v2);
            if (!BOX64ENV(dynarec_fastnan)) {
                FCMP_D(fcc0, v1, v2, cUN);
                BCNEZ_MARK(fcc0);
                FCMP_D(fcc1, d0, d0, cOR);
                BCNEZ_MARK(fcc1);
                FNEG_D(d0, d0);
            }
            MARK;
            VOR_V(v0, v1, v1);
            VEXTRINS_D(v0, d0, 0);
            break;
        case 0x59:
            INST_NAME("VMULSD Gx, Vx, Ex");
            nextop = F8;
            GETVYx(v1, 0);
            GETEYSD(v2, 0, 0);
            GETGYx_empty(v0);
            d0 = fpu_get_scratch(dyn);
            FMUL_D(d0, v1, v2);
            if (!BOX64ENV(dynarec_fastnan)) {
                FCMP_D(fcc0, v1, v2, cUN);
                BCNEZ_MARK(fcc0);
                FCMP_D(fcc1, d0, d0, cOR);
                BCNEZ_MARK(fcc1);
                FNEG_D(d0, d0);
            }
            MARK;
            VOR_V(v0, v1, v1);
            VEXTRINS_D(v0, d0, 0);
            break;
        case 0x5C:
            INST_NAME("VSUBSD Gx, Vx, Ex");
            nextop = F8;
            GETVYx(v1, 0);
            GETEYSD(v2, 0, 0);
            GETGYx_empty(v0);
            d0 = fpu_get_scratch(dyn);
            FSUB_D(d0, v1, v2);
            if (!BOX64ENV(dynarec_fastnan)) {
                FCMP_D(fcc0, v1, v2, cUN);
                BCNEZ_MARK(fcc0);
                FCMP_D(fcc1, d0, d0, cOR);
                BCNEZ_MARK(fcc1);
                FNEG_D(d0, d0);
            }
            MARK;
            VOR_V(v0, v1, v1);
            VEXTRINS_D(v0, d0, 0);
            break;
        case 0x5E:
            INST_NAME("VDIVSD Gx, Vx, Ex");
            nextop = F8;
            GETVYx(v1, 0);
            GETEYSD(v2, 0, 0);
            GETGYx_empty(v0);
            d0 = fpu_get_scratch(dyn);
            FDIV_D(d0, v1, v2);
            if (!BOX64ENV(dynarec_fastnan)) {
                FCMP_D(fcc0, v1, v2, cUN);
                BCNEZ_MARK(fcc0);
                FCMP_D(fcc1, d0, d0, cOR);
                BCNEZ_MARK(fcc1);
                FNEG_D(d0, d0);
            }
            MARK;
            VOR_V(v0, v1, v1);
            VEXTRINS_D(v0, d0, 0);
            break;
        case 0x70:
            INST_NAME("VPSHUFLW Gx, Ex, Ib");
            nextop = F8;
            GETGY_empty_EY_xy(v0, v1, 1);
            u8 = F8;
            d0 = fpu_get_scratch(dyn);
            if (v0 != v1) {
                VSHUF4Ixy(H, v0, v1, u8);
                VEXTRINSxy(D, v0, v1, VEXTRINS_IMM_4_0(1, 1));
            } else {
                VSHUF4Ixy(H, d0, v1, u8);
                VEXTRINSxy(D, v0, d0, VEXTRINS_IMM_4_0(0, 0));
            }
            break;
        case 0x7C:
            INST_NAME("VHADDPS Gx, Vx, Ex");
            nextop = F8;
            GETGY_empty_VYEY_xy(v0, v1, v2, 0);
            q0 = fpu_get_scratch(dyn);
            VPICKEVxy(W, q0, v2, v1);
            VPICKODxy(W, v0, v2, v1);
            if (!BOX64ENV(dynarec_fastnan)) {
                d0 = fpu_get_scratch(dyn);
                d1 = fpu_get_scratch(dyn);
                VFCMPxy(S, d0, q0, v0, cUN);
            }
            VFADDxy(S, v0, q0, v0);
            if (!BOX64ENV(dynarec_fastnan)) {
                VFCMPxy(S, d1, v0, v0, cUN);
                VANDN_Vxy(d0, d0, d1);
                VLDIxy(d1, (0b010 << 9) | 0b1111111100);
                VSLLIxy(W, d1, d1, 20); // broadcast 0xFFC00000
                VBITSEL_Vxy(v0, v0, d1, d0);
            }
            break;
        case 0x7D:
            INST_NAME("VHSUBPS Gx, Vx, Ex");
            nextop = F8;
            GETGY_empty_VYEY_xy(v0, v1, v2, 0);
            q0 = fpu_get_scratch(dyn);
            VPICKEVxy(W, q0, v2, v1);
            VPICKODxy(W, v0, v2, v1);
            if (!BOX64ENV(dynarec_fastnan)) {
                d0 = fpu_get_scratch(dyn);
                d1 = fpu_get_scratch(dyn);
                VFCMPxy(S, d0, q0, v0, cUN);
            }
            VFSUBxy(S, v0, q0, v0);
            if (!BOX64ENV(dynarec_fastnan)) {
                VFCMPxy(S, d1, v0, v0, cUN);
                VANDN_Vxy(d0, d0, d1);
                VLDIxy(d1, (0b010 << 9) | 0b1111111100);
                VSLLIxy(W, d1, d1, 20); // broadcast 0xFFC00000
                VBITSEL_Vxy(v0, v0, d1, d0);
            }
            break;
        case 0xD0:
            INST_NAME("VADDSUBPS Gx, Vx, Ex");
            nextop = F8;
            GETGY_empty_VYEY_xy(v0, v1, v2, 0);
            if (!BOX64ENV(dynarec_fastnan)) {
                d0 = fpu_get_scratch(dyn);
                d1 = fpu_get_scratch(dyn);
                VFCMPxy(S, d0, v1, v2, cUN);
            }
            q0 = fpu_get_scratch(dyn);
            VFSUBxy(S, q0, v1, v2);
            VFADDxy(S, v0, v1, v2);
            VEXTRINSxy(W, v0, q0, VEXTRINS_IMM_4_0(0, 0));
            VEXTRINSxy(W, v0, q0, VEXTRINS_IMM_4_0(2, 2));
            if (!BOX64ENV(dynarec_fastnan)) {
                VFCMPxy(S, d1, v0, v0, cUN);
                VANDN_Vxy(d0, d0, d1);
                VLDIxy(d1, (0b010 << 9) | 0b1111111100);
                VSLLIxy(W, d1, d1, 20); // broadcast 0xFFC00000
                VBITSEL_Vxy(v0, v0, d1, d0);
            }
            break;
        case 0xF0:
            INST_NAME("VLDDQU Gx, Ex");
            nextop = F8;
            if (MODREG) {
                GETGY_empty_EY_xy(q0, q1, 0);
                if (vex.l) {
                    XVOR_V(q0, q1, q1);
                } else {
                    VOR_V(q0, q1, q1);
                }
            } else {
                GETGYxy_empty(q0);
                SMREAD();
                addr = geted(dyn, addr, ninst, nextop, &ed, x2, x1, &fixedaddress, rex, NULL, 1, 0);
                if (vex.l) {
                    XVLD(q0, ed, fixedaddress);
                } else {
                    VLD(q0, ed, fixedaddress);
                }
            }
            break;
        default:
            DEFAULT;
    }
    return addr;
}
