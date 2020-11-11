//===-- RegisterContextFreeBSDTests.cpp -----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

// clang-format off
#include <sys/types.h>
#include <machine/reg.h>
// clang-format on

#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "Plugins/Process/Utility/lldb-x86-register-enums.h"
#include "Plugins/Process/Utility/RegisterContextFreeBSD_i386.h"
#include "Plugins/Process/Utility/RegisterContextFreeBSD_x86_64.h"

using namespace lldb;
using namespace lldb_private;

std::pair<size_t, size_t> GetRegParams(RegisterInfoInterface &ctx,
                                       uint32_t reg) {
  const RegisterInfo &info = ctx.GetRegisterInfo()[reg];
  return {info.byte_offset, info.byte_size};
}

#define ASSERT_OFF(regname, offset, size)                                      \
  EXPECT_THAT(GetRegParams(reg_ctx, lldb_##regname),                           \
              ::testing::Pair(offset + base_offset, size))

#if defined(__x86_64__)

#define ASSERT_GPR_X86_64(regname)                                             \
  EXPECT_THAT(                                                                 \
      GetRegParams(reg_ctx, lldb_##regname##_x86_64),                          \
      ::testing::Pair(offsetof(reg, r_##regname), sizeof(reg::r_##regname)))

TEST(RegisterContextFreeBSDTest, x86_64) {
  ArchSpec arch{"x86_64-unknown-freebsd12.2"};
  RegisterContextFreeBSD_x86_64 reg_ctx{arch};

  ASSERT_GPR_X86_64(r15);
  ASSERT_GPR_X86_64(r14);
  ASSERT_GPR_X86_64(r13);
  ASSERT_GPR_X86_64(r12);
  ASSERT_GPR_X86_64(r11);
  ASSERT_GPR_X86_64(r10);
  ASSERT_GPR_X86_64(r9);
  ASSERT_GPR_X86_64(r8);
  ASSERT_GPR_X86_64(rdi);
  ASSERT_GPR_X86_64(rsi);
  ASSERT_GPR_X86_64(rbp);
  ASSERT_GPR_X86_64(rbx);
  ASSERT_GPR_X86_64(rdx);
  ASSERT_GPR_X86_64(rcx);
  ASSERT_GPR_X86_64(rax);
  ASSERT_GPR_X86_64(fs);
  ASSERT_GPR_X86_64(gs);
  ASSERT_GPR_X86_64(es);
  ASSERT_GPR_X86_64(ds);
  ASSERT_GPR_X86_64(rip);
  ASSERT_GPR_X86_64(cs);
  ASSERT_GPR_X86_64(rflags);
  ASSERT_GPR_X86_64(rsp);
  ASSERT_GPR_X86_64(ss);

  // fctrl is the first FPR field, it is used to determine offset of the whole
  // FPR struct
  size_t base_offset = reg_ctx.GetRegisterInfo()[lldb_fctrl_x86_64].byte_offset;

  // assert against FXSAVE struct
  ASSERT_OFF(fctrl_x86_64, 0x00, 2);
  ASSERT_OFF(fstat_x86_64, 0x02, 2);
  // TODO: This is a known bug, abridged ftag should is 8 bits in length.
  ASSERT_OFF(ftag_x86_64, 0x04, 2);
  ASSERT_OFF(fop_x86_64, 0x06, 2);
  // NB: Technically fiseg/foseg are 16-bit long and the higher 16 bits
  // are reserved.  However, we use them to access/recombine 64-bit FIP/FDP.
  ASSERT_OFF(fioff_x86_64, 0x08, 4);
  ASSERT_OFF(fiseg_x86_64, 0x0C, 4);
  ASSERT_OFF(fooff_x86_64, 0x10, 4);
  ASSERT_OFF(foseg_x86_64, 0x14, 4);
  ASSERT_OFF(mxcsr_x86_64, 0x18, 4);
  ASSERT_OFF(mxcsrmask_x86_64, 0x1C, 4);
  ASSERT_OFF(st0_x86_64, 0x20, 10);
  ASSERT_OFF(st1_x86_64, 0x30, 10);
  ASSERT_OFF(st2_x86_64, 0x40, 10);
  ASSERT_OFF(st3_x86_64, 0x50, 10);
  ASSERT_OFF(st4_x86_64, 0x60, 10);
  ASSERT_OFF(st5_x86_64, 0x70, 10);
  ASSERT_OFF(st6_x86_64, 0x80, 10);
  ASSERT_OFF(st7_x86_64, 0x90, 10);
  ASSERT_OFF(mm0_x86_64, 0x20, 8);
  ASSERT_OFF(mm1_x86_64, 0x30, 8);
  ASSERT_OFF(mm2_x86_64, 0x40, 8);
  ASSERT_OFF(mm3_x86_64, 0x50, 8);
  ASSERT_OFF(mm4_x86_64, 0x60, 8);
  ASSERT_OFF(mm5_x86_64, 0x70, 8);
  ASSERT_OFF(mm6_x86_64, 0x80, 8);
  ASSERT_OFF(mm7_x86_64, 0x90, 8);
  ASSERT_OFF(xmm0_x86_64, 0xA0, 16);
  ASSERT_OFF(xmm1_x86_64, 0xB0, 16);
  ASSERT_OFF(xmm2_x86_64, 0xC0, 16);
  ASSERT_OFF(xmm3_x86_64, 0xD0, 16);
  ASSERT_OFF(xmm4_x86_64, 0xE0, 16);
  ASSERT_OFF(xmm5_x86_64, 0xF0, 16);
  ASSERT_OFF(xmm6_x86_64, 0x100, 16);
  ASSERT_OFF(xmm7_x86_64, 0x110, 16);
  ASSERT_OFF(xmm8_x86_64, 0x120, 16);
  ASSERT_OFF(xmm9_x86_64, 0x130, 16);
  ASSERT_OFF(xmm10_x86_64, 0x140, 16);
  ASSERT_OFF(xmm11_x86_64, 0x150, 16);
  ASSERT_OFF(xmm12_x86_64, 0x160, 16);
  ASSERT_OFF(xmm13_x86_64, 0x170, 16);
  ASSERT_OFF(xmm14_x86_64, 0x180, 16);
  ASSERT_OFF(xmm15_x86_64, 0x190, 16);
}
#endif

#if defined(__i386__) || defined(__x86_64__)

#define ASSERT_GPR_I386(regname)                                               \
  EXPECT_THAT(GetRegParams(reg_ctx, lldb_##regname##_i386),                    \
              ::testing::Pair(offsetof(native_i386_regs, r_##regname),         \
                              sizeof(native_i386_regs::r_##regname)))

TEST(RegisterContextFreeBSDTest, i386) {
  ArchSpec arch{"i686-unknown-freebsd12.2"};
  RegisterContextFreeBSD_i386 reg_ctx{arch};

#if defined(__i386__)
  using native_i386_regs = ::reg;
#else
  using native_i386_regs = ::reg32;
#endif

  ASSERT_GPR_I386(fs);
  ASSERT_GPR_I386(es);
  ASSERT_GPR_I386(ds);
  ASSERT_GPR_I386(edi);
  ASSERT_GPR_I386(esi);
  ASSERT_GPR_I386(ebp);
  ASSERT_GPR_I386(ebx);
  ASSERT_GPR_I386(edx);
  ASSERT_GPR_I386(ecx);
  ASSERT_GPR_I386(eax);
  ASSERT_GPR_I386(eip);
  ASSERT_GPR_I386(cs);
  ASSERT_GPR_I386(eflags);
  ASSERT_GPR_I386(esp);
  ASSERT_GPR_I386(ss);
  ASSERT_GPR_I386(gs);

  // fctrl is the first FPR field, it is used to determine offset of the whole
  // FPR struct
  size_t base_offset = reg_ctx.GetRegisterInfo()[lldb_fctrl_i386].byte_offset;

  // assert against FXSAVE struct
  ASSERT_OFF(fctrl_i386, 0x00, 2);
  ASSERT_OFF(fstat_i386, 0x02, 2);
  // TODO: This is a known bug, abridged ftag should is 8 bits in length.
  ASSERT_OFF(ftag_i386, 0x04, 2);
  ASSERT_OFF(fop_i386, 0x06, 2);
  // NB: Technically fiseg/foseg are 16-bit long and the higher 16 bits
  // are reserved.  However, we use them to access/recombine 64-bit FIP/FDP.
  ASSERT_OFF(fioff_i386, 0x08, 4);
  ASSERT_OFF(fiseg_i386, 0x0C, 4);
  ASSERT_OFF(fooff_i386, 0x10, 4);
  ASSERT_OFF(foseg_i386, 0x14, 4);
  ASSERT_OFF(mxcsr_i386, 0x18, 4);
  ASSERT_OFF(mxcsrmask_i386, 0x1C, 4);
  ASSERT_OFF(st0_i386, 0x20, 10);
  ASSERT_OFF(st1_i386, 0x30, 10);
  ASSERT_OFF(st2_i386, 0x40, 10);
  ASSERT_OFF(st3_i386, 0x50, 10);
  ASSERT_OFF(st4_i386, 0x60, 10);
  ASSERT_OFF(st5_i386, 0x70, 10);
  ASSERT_OFF(st6_i386, 0x80, 10);
  ASSERT_OFF(st7_i386, 0x90, 10);
  ASSERT_OFF(mm0_i386, 0x20, 8);
  ASSERT_OFF(mm1_i386, 0x30, 8);
  ASSERT_OFF(mm2_i386, 0x40, 8);
  ASSERT_OFF(mm3_i386, 0x50, 8);
  ASSERT_OFF(mm4_i386, 0x60, 8);
  ASSERT_OFF(mm5_i386, 0x70, 8);
  ASSERT_OFF(mm6_i386, 0x80, 8);
  ASSERT_OFF(mm7_i386, 0x90, 8);
  ASSERT_OFF(xmm0_i386, 0xA0, 16);
  ASSERT_OFF(xmm1_i386, 0xB0, 16);
  ASSERT_OFF(xmm2_i386, 0xC0, 16);
  ASSERT_OFF(xmm3_i386, 0xD0, 16);
  ASSERT_OFF(xmm4_i386, 0xE0, 16);
  ASSERT_OFF(xmm5_i386, 0xF0, 16);
  ASSERT_OFF(xmm6_i386, 0x100, 16);
  ASSERT_OFF(xmm7_i386, 0x110, 16);
}
#endif
