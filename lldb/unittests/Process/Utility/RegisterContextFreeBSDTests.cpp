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
}
#endif
