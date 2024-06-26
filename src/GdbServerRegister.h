/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_GDB_SERVER_REGISTER_H_
#define RR_GDB_SERVER_REGISTER_H_

namespace rr {

/**
 * This is the register numbering used by GDB.
 */
enum GdbServerRegister {
  DREG_EAX,
  DREG_ECX,
  DREG_EDX,
  DREG_EBX,
  DREG_ESP,
  DREG_EBP,
  DREG_ESI,
  DREG_EDI,
  DREG_EIP,
  DREG_EFLAGS,
  DREG_CS,
  DREG_SS,
  DREG_DS,
  DREG_ES,
  DREG_FS,
  DREG_GS,
  DREG_FIRST_FXSAVE_REG,
  DREG_ST0 = DREG_FIRST_FXSAVE_REG,
  DREG_ST1,
  DREG_ST2,
  DREG_ST3,
  DREG_ST4,
  DREG_ST5,
  DREG_ST6,
  DREG_ST7,
  // These are the names GDB gives the registers.
  DREG_FCTRL,
  DREG_FSTAT,
  DREG_FTAG,
  DREG_FISEG,
  DREG_FIOFF,
  DREG_FOSEG,
  DREG_FOOFF,
  DREG_FOP,
  DREG_XMM0,
  DREG_XMM1,
  DREG_XMM2,
  DREG_XMM3,
  DREG_XMM4,
  DREG_XMM5,
  DREG_XMM6,
  DREG_XMM7,
  DREG_MXCSR,
  // XXX the last fxsave reg on *x86*
  DREG_LAST_FXSAVE_REG = DREG_MXCSR,
  DREG_ORIG_EAX,
  DREG_YMM0H,
  DREG_YMM1H,
  DREG_YMM2H,
  DREG_YMM3H,
  DREG_YMM4H,
  DREG_YMM5H,
  DREG_YMM6H,
  DREG_YMM7H,
  DREG_PKRU,
  DREG_NUM_LINUX_I386,
  // Last register we can find in user_regs_struct
  // (except for orig_eax).
  DREG_NUM_USER_REGS = DREG_GS + 1,

  // x86-64 register numbers
  DREG_RAX = 0,
  DREG_RBX,
  DREG_RCX,
  DREG_RDX,
  DREG_RSI,
  DREG_RDI,
  DREG_RBP,
  DREG_RSP,
  DREG_R8,
  DREG_R9,
  DREG_R10,
  DREG_R11,
  DREG_R12,
  DREG_R13,
  DREG_R14,
  DREG_R15,
  DREG_RIP,
  // Things get a little tricky here, because x86-64 has some registers
  // named identically to its x86 counterpart, but we've used the names
  // in the x86 register definitions above, and the numbers they need
  // to represent are different.  Hence the unique names here.
  DREG_64_EFLAGS,
  DREG_64_CS,
  DREG_64_SS,
  DREG_64_DS,
  DREG_64_ES,
  DREG_64_FS,
  DREG_64_GS,
  DREG_64_FIRST_FXSAVE_REG,
  DREG_64_ST0 = DREG_64_FIRST_FXSAVE_REG,
  DREG_64_ST1,
  DREG_64_ST2,
  DREG_64_ST3,
  DREG_64_ST4,
  DREG_64_ST5,
  DREG_64_ST6,
  DREG_64_ST7,
  // These are the names GDB gives the registers.
  DREG_64_FCTRL,
  DREG_64_FSTAT,
  DREG_64_FTAG,
  DREG_64_FISEG,
  DREG_64_FIOFF,
  DREG_64_FOSEG,
  DREG_64_FOOFF,
  DREG_64_FOP,
  DREG_64_XMM0,
  DREG_64_XMM1,
  DREG_64_XMM2,
  DREG_64_XMM3,
  DREG_64_XMM4,
  DREG_64_XMM5,
  DREG_64_XMM6,
  DREG_64_XMM7,
  DREG_64_XMM8,
  DREG_64_XMM9,
  DREG_64_XMM10,
  DREG_64_XMM11,
  DREG_64_XMM12,
  DREG_64_XMM13,
  DREG_64_XMM14,
  DREG_64_XMM15,
  DREG_64_MXCSR,
  DREG_64_LAST_FXSAVE_REG = DREG_64_MXCSR,
  DREG_ORIG_RAX,
  DREG_FS_BASE,
  DREG_GS_BASE,
  DREG_64_YMM0H,
  DREG_64_YMM1H,
  DREG_64_YMM2H,
  DREG_64_YMM3H,
  DREG_64_YMM4H,
  DREG_64_YMM5H,
  DREG_64_YMM6H,
  DREG_64_YMM7H,
  DREG_64_YMM8H,
  DREG_64_YMM9H,
  DREG_64_YMM10H,
  DREG_64_YMM11H,
  DREG_64_YMM12H,
  DREG_64_YMM13H,
  DREG_64_YMM14H,
  DREG_64_YMM15H,
  DREG_64_PKRU,
  DREG_NUM_LINUX_X86_64,
  // Last register we can find in user_regs_struct (except for orig_rax).
  DREG_64_NUM_USER_REGS = DREG_64_GS + 1,

  // aarch64-core.xml
  DREG_X0 = 0,
  DREG_X1,
  DREG_X2,
  DREG_X3,
  DREG_X4,
  DREG_X5,
  DREG_X6,
  DREG_X7,
  DREG_X8,
  DREG_X9,
  DREG_X10,
  DREG_X11,
  DREG_X12,
  DREG_X13,
  DREG_X14,
  DREG_X15,
  DREG_X16,
  DREG_X17,
  DREG_X18,
  DREG_X19,
  DREG_X20,
  DREG_X21,
  DREG_X22,
  DREG_X23,
  DREG_X24,
  DREG_X25,
  DREG_X26,
  DREG_X27,
  DREG_X28,
  DREG_X29,
  DREG_X30,
  DREG_SP,
  DREG_PC,
  DREG_CPSR,

  // aarch64-fpu.xml
  DREG_V0 = 34,
  DREG_V1,
  DREG_V2,
  DREG_V3,
  DREG_V4,
  DREG_V5,
  DREG_V6,
  DREG_V7,
  DREG_V8,
  DREG_V9,
  DREG_V10,
  DREG_V11,
  DREG_V12,
  DREG_V13,
  DREG_V14,
  DREG_V15,
  DREG_V16,
  DREG_V17,
  DREG_V18,
  DREG_V19,
  DREG_V20,
  DREG_V21,
  DREG_V22,
  DREG_V23,
  DREG_V24,
  DREG_V25,
  DREG_V26,
  DREG_V27,
  DREG_V28,
  DREG_V29,
  DREG_V30,
  DREG_V31,
  DREG_FPSR,
  DREG_FPCR,

  DREG_NUM_LINUX_AARCH64 = DREG_FPCR + 1,
};

} // namespace rr

#endif /* RR_GDB_SERVER_REGISTER_H_ */
