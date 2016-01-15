/* ----------------------------------------------------------------------------
 Copyright (c) 2013,2014 Diogo Behrens
 Copyright (c) 2016 Norman Rink

 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included in
 all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 THE SOFTWARE.
 --------------------------------------------------------------------------- */

#include <cstdio>
#include <cstdlib>
#include <vector>
#include <map>
#include <libgen.h> // basename
#include <string.h>
#include <stdarg.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <stdlib.h> // rand_r
#include <unistd.h>
#include <cassert>
#include "pin.H"

/* ----------------------------------------------------------------------------
 * types
 * ------------------------------------------------------------------------- */

typedef enum _cmd_t {NONE = 0, CF, RVAL, WVAL, RADDR, WADDR, RREG, WREG,
                     TXT, COUNT_CMD_T} cmd_t;
static const char*
cmd_names[] = {"NONE", "CF", "RVAL", "WVAL", "RADDR", "WADDR", "RREG", "WREG",
                "TXT"}; 

/* ----------------------------------------------------------------------------
 * definitions 
 * ------------------------------------------------------------------------- */

#define DIE(X) die(1, "%s:%d: *** %s\n", __FILE__, __LINE__, X);
#define ULLONG unsigned long long

/* ----------------------------------------------------------------------------
 * state
 * ------------------------------------------------------------------------- */

static cmd_t cmd            = NONE; // command to be executed
static UINT64 tip           = 0;    // target IP address
static UINT64 tit           = 0;    // iteration at target IP address
static UINT64 dip           = 0;    // detach IP address
static UINT64 dit           = 0;    // iteration at detach IP address

static map<UINT64, UINT64> ip_iters;
static map<UINT64, string> ip_infos;
static vector<string> func;         // functions to find
static vector<UINT64> cfunc;        // functions iteration counter

static FILE* log_file  = NULL;  // log file (NULL prints on screen)
static double start_ts = 0;
static unsigned seed   = 0;     // seed (0 no random)
static unsigned iseed  = 0;     // initial seed (for logging output)
static ADDRINT mask    = 0x1;   // error mask (determined with seed)
static INT32 sel       = -1;    // selector of registers (if set, ignore seed)
static bool detach     = false; // detach after inject
static unsigned thread = 0;     // target thread

/* ----------------------------------------------------------------------------
 * state for text errors
 * ------------------------------------------------------------------------- */
static unsigned char text[256];

/* ----------------------------------------------------------------------------
 * helper functions
 * ------------------------------------------------------------------------- */

/* select command from command line argument */
static cmd_t
cmd_select(const char* cmd) {
    if (strcmp(cmd, "CF")    == 0) return CF;
    if (strcmp(cmd, "WADDR") == 0) return WADDR;
    if (strcmp(cmd, "RADDR") == 0) return RADDR;
    if (strcmp(cmd, "WVAL")  == 0) return WVAL;
    if (strcmp(cmd, "RVAL")  == 0) return RVAL;
    if (strcmp(cmd, "RREG")  == 0) return RREG;
    if (strcmp(cmd, "WREG")  == 0) return WREG;
    if (strcmp(cmd, "TXT")   == 0) return TXT;
    return NONE;
}

/* read current time in seconds */
static inline double
now()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return ((double) tv.tv_sec) + ((double)tv.tv_usec)/1000000.0;
}

/* log informantion */
static void
info(CONTEXT* ctx, THREADID id, ADDRINT ip, const char* fmt, ...)
{
    INT32 col, line;
    std::string fname;
    PIN_LockClient();
    PIN_GetSourceLocation(ip, &col, &line, &fname);
    PIN_UnlockClient();
    char* file = basename((char*) fname.c_str());

    char bfmt [1024];
    sprintf(bfmt,
            "[%s:%5d, IP = %p, t = %d]\n"
            "\t%s\n",
            file, line, (void*) ip,
            id,
            fmt);

    // write into the log file if log_file set, otherwise write to stderr
    if (log_file) {
        va_list ap;
        va_start(ap, fmt);
        vfprintf(log_file, bfmt, ap);
        va_end(ap);
    } else {
        va_list ap;
        va_start(ap, fmt);
        vfprintf(stderr, bfmt, ap);
        va_end(ap);
    }
#ifdef DISASM
/* NOTE: If disassembling is switched on, disassembled instructions are dumped
   to <stdout> as they are executed. Hence we duplicate the output from calls
   to 'info' to <stdout> so that it can be seen where (or rather, when) in
   the instruction stream faults were injected. */
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stdout, bfmt, ap);
    va_end(ap);
#endif /* DISASM */
    // breakpoint in debugger (if connected)
    // avoid implicit execution from new context:
    // if (ctx) PIN_ApplicationBreakpoint(ctx, id, FALSE, "fault injected");
}

/* fatal error happened, terminate */
static void
die(int retcode, const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    PIN_ExitProcess(retcode);
}

/* return 1 if the current thread is the desired target thread */
static ADDRINT
right_thread(THREADID id)
{
    if (id == thread) return 1;
    else return 0;
}

static UINT32
get_sel_or_random() {
  UINT32 res;
  if (sel >= 0) {
      res = sel;
  } else {
      if (!seed) res = 0;
      else res = rand_r(&seed);
  }
  return res;
}

#ifdef DISASM
std::map<ADDRINT,std::string> assembly;

/* NOTE: Disassembled instructions are dumped to <stdout>. This is because
   output to <stderr> is trawled by the Python script "coverage.py". Hence
   output to <stderr> should be kept small in order to reduce the runtime
   of "coverage.py". */
static VOID
disasm(THREADID id, CONTEXT* ctx, ADDRINT ip, UINT32 size)
{
  if (!right_thread(id)) return;

  ADDRINT reg_ip = (ADDRINT) PIN_GetContextReg(ctx, REG_INST_PTR);
  fprintf(stdout, "0x%lX (ip=0x%lX): (size=%d) ", ip, reg_ip, size);
  unsigned char *addr = (unsigned char*)ip;
  for (unsigned i = 0; i < size; i++)
    fprintf(stdout, "%02X.", addr[i]);
  fprintf(stdout, " %s\n", assembly[ip].c_str());
}

static VOID
targetname(THREADID id, CONTEXT* ctx, ADDRINT target)
{
  if (!right_thread(id)) return;
      
  std::string name = RTN_FindNameByAddress(target);    
  fprintf(stdout, "name of target at address 0x%lX: %s\n", target, name.c_str());
}
#endif /* DISASM */

/* ----------------------------------------------------------------------------
 * fault injection
 * ----------------------------------------------------------------------------
 * inject_* functions are called when the trigger is found.
 * ------------------------------------------------------------------------- */
static UINT64 ip_cnt = 0;
static UINT64 dip_cnt = 0;

static BOOL
at_ip_iteration(THREADID id) {
  if (!right_thread(id)) return 0;
#ifdef VERBOSE_INFO
  fprintf(stderr, "iter %lu, tit %lu\n", ip_cnt, tit);
#endif /* VERBOSE_INFO */
  return (ip_cnt == tit);
}

static void
count_ip(THREADID id) {
  if (!right_thread(id)) return;
  ++ip_cnt;
}

static BOOL
count_dip(THREADID id) {
  if (!right_thread(id)) return 0;
  ++dip_cnt;
  return dip_cnt == dit;
}

static VOID
inject_detach(THREADID id, CONTEXT* ctx)
{
  PIN_RemoveFiniFunctions();
  PIN_Detach();
}

static VOID
inject_txt(THREADID id, CONTEXT* ctx, ADDRINT ins, ADDRINT next, UINT32 size)
{
  // get current IP from context
  ADDRINT ip = (ADDRINT)PIN_GetContextReg(ctx, REG_INST_PTR);

  // copy original function in text area
  PIN_SafeCopy(text, (void*)ip, size);

  // truncate mask to a single byte
  ADDRINT tmp = mask & 0xFF;
  // if the mask became 0, use mask 1 instead (unless it was
  // given as 0 from user input)
  if (tmp == 0 && mask != 0) mask = 0x01;
  else mask = tmp;

  // get target byte and make idx fit instruction size
  INT32 idx = get_sel_or_random() % size;

  // save un-corrupted byte
  unsigned char obyte = text[idx];
  // calculate corrupted byte
  unsigned char nbyte = text[idx] ^ mask;
  // corrupt code
  text[idx] = nbyte;

  // write new opcode to code segment
  const long pg_size = sysconf(_SC_PAGESIZE);
  const long ip_addr = (long)ip;
  const long pg_addr = (ip_addr & ~(pg_size-1));
  long *const page = (long *const)pg_addr;
  // must call 'mprotect' to make the code segment writeable
  if (mprotect(page, pg_size, PROT_WRITE | PROT_EXEC))
    DIE("cannot change access rights for code segment");
  // change the opcode in the code segment
  PIN_SafeCopy((void*) ip, text, size);
  // revoke the right to write to the code segment
  if (mprotect(page, pg_size, PROT_READ | PROT_EXEC))
    DIE("cannot reset access rights for code segment");

  // log info
  info(ctx, id, ip, "ip' = %p, size = %u, mask = %llu, idx = %d, "
       "byte = 0x%x, byte' = 0x%x",
       next, size, (ULLONG) mask, idx, obyte, nbyte);

  // jump to context to make sure the instruction pointer is re-read
  // NOTE: The call to 'PIN_ApplicationBreakpoint' at the end of the 'info'
  // function also leads to an execution of context 'ctx'.
  PIN_ExecuteAt(ctx);
}

static VOID
inject_cf(THREADID id, CONTEXT* ctx)
{
  ADDRINT ip  = (ADDRINT)PIN_GetContextReg(ctx, REG_INST_PTR);
  ADDRINT aip = ip ^ mask;
  PIN_SetContextReg(ctx, REG_INST_PTR, aip);

  info(ctx, id, ip, "ip = %p, ip' = %p", (void*)ip, (void*)aip);

  // jumpt to new context
  PIN_ExecuteAt(ctx);
}

static ADDRINT storage = 0xdeadbeef;
static VOID
store(CONTEXT* ctx, ADDRINT addr) {
#ifdef VERBOSE_INFO
  fprintf(stderr, "storing address %lx\n", addr);
#endif /* VERBOSE_INFO */
  storage = addr;
}

static inline UINT32
min(UINT32 x, UINT32 y) {
  return (x < y) ? x : y;
}

static VOID
inject_value(CONTEXT* ctx, THREADID id, ADDRINT ip,
             UINT32 size, UINT32 access, UINT32 op)
{
  ADDRINT addr = storage;;
#ifdef VERBOSE_INFO
  fprintf(stderr, "value injection at address %lx\n", addr);
#endif /* VERBOSE_INFO */
  
  uint64_t correct = 0;
  PIN_SafeCopy((void*)&correct, (void*)addr, min(size, sizeof(correct)));

  uint64_t error = correct ^ mask;
  PIN_SafeCopy((void*)addr, &error, min(size, sizeof(correct)));

  info(ctx, id, ip, "access = %u, size = %u, value = %llx, value' = %llx,"
       " addr = %p, op = %u",
       access, size,
       (ULLONG)correct, (ULLONG)error,
       (void*)addr, op);
}

static ADDRINT
pass_addr(ADDRINT addr) {
  return addr;
}

static ADDRINT
inject_addr(CONTEXT* ctx, THREADID id, ADDRINT ip, ADDRINT addr,
            UINT32 size, UINT32 access, UINT32 op)
{
#ifdef VERBOSE_INFO
  fprintf(stderr, "manipulating address %lx\n", addr);
#endif /* VERBOSE_INFO */

  ADDRINT addrp = addr ^ mask;

  info(ctx, id, ip, "access = %u, size = %u, addr = %p, addr' = %p, op = %u",
       access, size,
       (void*)addr,
       (void*)addrp,
       op);

  return addrp;
}

static VOID
inject_reg(THREADID id, ADDRINT ip, CONTEXT* ctx, REG reg)
{
  const string& rname = REG_StringShort(reg);
  reg = REG_FullRegName(reg);

  //avoid 0x100 if register is RFLAGS

  ADDRINT aip = (ADDRINT) PIN_GetContextReg(ctx, REG_INST_PTR);
  ADDRINT rv  = (ADDRINT) PIN_GetContextReg(ctx, reg);
  ADDRINT rvx = rv ^ mask;
  PIN_SetContextReg(ctx, reg, rvx);

  info(ctx, id, ip, "at ip %p, %s = %p, %s' = %p",
       (void*)aip,
       rname.c_str(), (void*)rv,
       rname.c_str(), (void*)rvx);

  // jump to new context
  // Note that re-executing the same instruction (at the same ip) within the
  // new context leads to an additional increment of the 'ip_cnt'. This is OK
  // since after the fault has been injected, the 'ip_cnt' is no longer needed.
  PIN_ExecuteAt(ctx);
}

/* ----------------------------------------------------------------------------
 * instrumentation
 * ----------------------------------------------------------------------------
 * instrument_* functions are called the first time an instructions is
 * executed, ie, when the instruction is not yet in Pin's cache.  These
 * functions add conditional calls to the injection functions.  There is one
 * instrument_x function for each command.
 * ------------------------------------------------------------------------- */

#ifdef DISASM
static inline VOID
instrument_disasm(INS ins, VOID* v)
{
  assembly[INS_Address(ins)] = INS_Disassemble(ins);
  INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) disasm,
                 IARG_THREAD_ID,
                 IARG_CONTEXT,
                 IARG_ADDRINT, INS_Address(ins),
                 IARG_UINT32, INS_Size(ins),
                 IARG_END);
  if (INS_IsDirectBranchOrCall(ins)) {
    ADDRINT target = INS_DirectBranchOrCallTargetAddress(ins);
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) targetname,
                   IARG_THREAD_ID,
                   IARG_CONTEXT,
                   IARG_ADDRINT, target,
                   IARG_END);
  }
}
#endif /* DISASM */

static inline VOID
instrument_cf(INS ins, VOID* v)
{
  INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)at_ip_iteration,
                   IARG_THREAD_ID,
                   IARG_END);
  INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)inject_cf,
                     IARG_THREAD_ID,
                     IARG_CONTEXT,
                     IARG_END);
}

static inline VOID
instrument_txt(INS ins, VOID* v)
{
  INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)at_ip_iteration,
                   IARG_THREAD_ID,
                   IARG_END);
  INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)inject_txt,
                     IARG_THREAD_ID,
                     IARG_CONTEXT,
                     IARG_ADDRINT, INS_Address(ins),
                     IARG_ADDRINT, INS_NextAddress(ins),
                     IARG_UINT32, INS_Size(ins),
                     IARG_END);
}

static inline VOID
instrument_addr(INS ins, VOID* v)
{
  // find possible faults in this instruction
  vector<UINT32> reads, writes;
  for (UINT32 op = 0; op < INS_MemoryOperandCount(ins); op++) {
    if (INS_MemoryOperandIsRead(ins, op))
      reads.push_back(op);
    if (INS_MemoryOperandIsWritten(ins, op)) 
      writes.push_back(op);
  }

  // get target operand or random index:
  UINT32 op = get_sel_or_random();
  // varables are initialized only to pacify the compiler:
  UINT32 rind = 0, wind = 0, raccess = 0, waccess = 0;

  if (cmd == RVAL || cmd == RADDR) {
    if (!reads.size()) DIE("FATAL: wrong injection command");
    rind = reads[op % reads.size()];
    // determine whether and how operand op is accessed
    // 0 = NONE, 1 = READ, 2 = WRITE, 3 = READ|WRITE)
    raccess = (INS_MemoryOperandIsRead(ins, rind) ? 1 : 0)
              | (INS_MemoryOperandIsWritten(ins, rind) ? 2 : 0);
    assert(raccess & 1);
  } else if (cmd == WVAL || cmd == WADDR) {
    if (!writes.size()) DIE("FATAL: wrong injection command");
    wind = writes[op % writes.size()];
    // determine whether and how operand op is accessed
    // 0 = NONE, 1 = READ, 2 = WRITE, 3 = READ|WRITE)
    waccess = (INS_MemoryOperandIsRead(ins, wind) ? 1 : 0)
              | (INS_MemoryOperandIsWritten(ins, wind) ? 2 : 0);
    assert(waccess & 2);
  } else {
    DIE("FATAL: wrong injection command");
  }
  fprintf(stderr, "op: %u, rind: %u, wind: %u\n", op, rind, wind);
        
  switch(cmd) {
  case RVAL: {
    UINT32 ind = rind, access = raccess;
    
    INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)at_ip_iteration,
                     IARG_THREAD_ID,
                     IARG_END);
    INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)store,
                       IARG_CONTEXT,
                       IARG_MEMORYOP_EA, ind,
                       IARG_END);

    INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)at_ip_iteration,
                       IARG_THREAD_ID,
                       IARG_END);
    INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)inject_value,
                       IARG_CONTEXT,
                       IARG_THREAD_ID,
                       IARG_INST_PTR,
                       IARG_UINT32, INS_MemoryOperandSize(ins, ind),
                       IARG_UINT32, access,
                       IARG_UINT32, ind,
                       IARG_END);
    break;
  }
  case WVAL: {
    UINT32 ind = wind, access = waccess;
    
    INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)at_ip_iteration,
                     IARG_THREAD_ID,
                     IARG_END);
    INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)store,
                       IARG_CONTEXT,
                       IARG_MEMORYOP_EA, ind,
                       IARG_END);

    if (INS_HasFallThrough(ins)) {
      INS_InsertIfCall(ins, IPOINT_AFTER, (AFUNPTR)at_ip_iteration,
                       IARG_THREAD_ID,
                       IARG_END);
      INS_InsertThenCall(ins, IPOINT_AFTER, (AFUNPTR)inject_value,
                         IARG_CONTEXT,
                         IARG_THREAD_ID,
                         IARG_INST_PTR,
                         IARG_UINT32, INS_MemoryOperandSize(ins, ind),
                         IARG_UINT32, access,
                         IARG_UINT32, ind,
                         IARG_END);
    }
    if (INS_IsBranchOrCall(ins) || INS_IsRet(ins)) {
      // Branch and return instructions do in fact not write to memory:
      assert(!INS_IsBranch(ins) && !INS_IsRet(ins));
      INS_InsertIfCall(ins, IPOINT_TAKEN_BRANCH, (AFUNPTR)at_ip_iteration,
                       IARG_THREAD_ID,
                       IARG_END);
      INS_InsertThenCall(ins, IPOINT_TAKEN_BRANCH, (AFUNPTR)inject_value,
                         IARG_CONTEXT,
                         IARG_THREAD_ID,
                         IARG_INST_PTR,
                         IARG_UINT32, INS_MemoryOperandSize(ins, ind),
                         IARG_UINT32, access,
                         IARG_UINT32, ind,
                         IARG_END);
    }
    break;
  }
  case RADDR: /* fall through */
  case WADDR: {
    UINT32 ind = (cmd == RADDR) ? rind : wind;
    UINT32 access = (cmd == RADDR) ? raccess : waccess;
    if (access == 3) DIE("{R|W}ADDR is currently not reliably implemented for "
                         "operands that simultaneously r/w memory.")

    REG scratch = PIN_ClaimToolRegister();
    if (scratch == REG_INVALID()) DIE("FATAL: No registers left");

    // Populate scratch register with correct address:
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)pass_addr,
                   IARG_MEMORYOP_EA, ind,
                   IARG_RETURN_REGS, scratch,
                   IARG_END);
    // Corrupt the scratch register only if we are at the the right iteration:
    INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)at_ip_iteration,
                     IARG_THREAD_ID,
                     IARG_END);
    INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)inject_addr,
                       IARG_CONTEXT,
                       IARG_THREAD_ID,
                       IARG_INST_PTR,
                       IARG_MEMORYOP_EA, ind,
                       IARG_UINT32, INS_MemoryOperandSize(ins, ind),
                       IARG_UINT32, access,
                       IARG_UINT32, ind,
                       IARG_RETURN_REGS, scratch,
                       IARG_CALL_ORDER, CALL_ORDER_LAST,
                       IARG_END);
    INS_RewriteMemoryOperand(ins, ind, scratch);
    break;
  }
  default: {
    DIE("We should not be here.")
  }
  }
}

static inline VOID
instrument_rreg(INS ins, VOID* v)
{
  if (!INS_MaxNumRRegs(ins)) DIE("FATAL: wrong injection command");

  UINT32 r = get_sel_or_random() % INS_MaxNumRRegs(ins);

  INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)at_ip_iteration,
                   IARG_THREAD_ID,
                   IARG_END);
  INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)inject_reg,
                     IARG_THREAD_ID,
                     IARG_INST_PTR,
                     IARG_CONTEXT,
                     IARG_UINT32, INS_RegR(ins, r),
                     IARG_END);
}

static inline VOID
instrument_wreg(INS ins, VOID* v)
{
  if (!INS_MaxNumWRegs(ins)) DIE("FATAL: wrong injection command");

  UINT32 r = get_sel_or_random() % INS_MaxNumWRegs(ins);

  if (INS_HasFallThrough(ins)) {
    INS_InsertIfCall(ins, IPOINT_AFTER, (AFUNPTR)at_ip_iteration,
                     IARG_THREAD_ID,
                     IARG_END);
    INS_InsertThenCall(ins, IPOINT_AFTER, (AFUNPTR)inject_reg,
                       IARG_THREAD_ID,
                       IARG_INST_PTR,
                       IARG_CONTEXT,
                       IARG_UINT32, INS_RegW(ins, r),
                       IARG_END);
  }
  if (INS_IsBranchOrCall(ins) || INS_IsRet(ins)) {
    INS_InsertIfCall(ins, IPOINT_TAKEN_BRANCH, (AFUNPTR)at_ip_iteration,
                     IARG_THREAD_ID,
                     IARG_END);
    INS_InsertThenCall(ins, IPOINT_TAKEN_BRANCH, (AFUNPTR)inject_reg,
                       IARG_THREAD_ID,
                       IARG_INST_PTR,
                       IARG_CONTEXT,
                       IARG_UINT32, INS_RegW(ins, r),
                       IARG_END);
  }
}
/* ----------------------------------------------------------------------------
 * monitor function
 * ------------------------------------------------------------------------- */
#define SEPARATOR " -- "

static VOID
instruction_info(CONTEXT* ctx, THREADID id, ADDRINT ip) {
  if (!right_thread(id)) return;

  if (!ip_iters.count(ip)) ip_iters[ip] = 0;
  ++ip_iters[ip];
            
  fprintf(stderr, "ip: 0x%lX"SEPARATOR"iteration: %ld%s\n", ip, ip_iters[ip], ip_infos[ip].c_str()); 
#ifdef VERBOSE_INFO  
  fprintf(stderr, "[");
  for (UINT32 i = REG_GR_BASE; i <= REG_GR_LAST; ++i) {
    const REG r = (REG) i;
    fprintf(stderr, "%s:%lx, ", REG_StringShort(r).c_str(), PIN_GetContextReg(ctx, r));
  }
  
  fprintf(stderr, "%s:%lx, %s:%lx]\n",
            REG_StringShort(REG_RIP).c_str(), PIN_GetContextReg(ctx, REG_RIP),
            REG_StringShort(REG_RFLAGS).c_str(), PIN_GetContextReg(ctx, REG_RFLAGS));
#endif /* VERBOSE_INFO */
}

static inline bool
cmd_possible(INS ins, cmd_t cmd) {
  switch(cmd) {
  case RREG:
    return INS_MaxNumRRegs(ins);
  case WREG:
    return INS_MaxNumWRegs(ins);
  case RVAL: /* fall through */
  case RADDR:
    for (UINT32 op = 0; op < INS_MemoryOperandCount(ins); op++) {
      if (INS_MemoryOperandIsRead(ins, op)) return true;
    }
    return false;
  case WVAL: /* fall through */
  case WADDR:
    for (UINT32 op = 0; op < INS_MemoryOperandCount(ins); op++) {
      if (INS_MemoryOperandIsWritten(ins, op)) return true;
    }
    return false;
  case CF: /* fall through */
  case TXT:
    return true;
  default:
    DIE("FATAL: Not a command");
    return false;
  }
}

static inline VOID
append_fmt(string& str, const char* fmt, ...) {
  char buffer [1024];
  va_list ap;

  va_start(ap, fmt);
  vsprintf(buffer, fmt, ap);
  va_end(ap);

  str += buffer; 
}
  
static VOID
extract_info(IMG img, VOID* v) {
  for (UINT32 i = 0; i < func.size(); ++i) {
    RTN foo = RTN_FindByName(img, func[i].c_str());
    if (!RTN_Valid(foo))
      continue;

    RTN_Open(foo);
    for (INS ins = RTN_InsHead(foo); INS_Valid(ins); ins = INS_Next(ins)) {
      string &ip_info = ip_infos[INS_Address(ins)];
      
      append_fmt(ip_info, SEPARATOR"assembly: %s", INS_Disassemble(ins).c_str());

      // read registers:  
      for (unsigned int r = 0; r < INS_MaxNumRRegs(ins); r++) {
        if (!r) append_fmt(ip_info, SEPARATOR"read:");
        REG reg = INS_RegR(ins, r);
        append_fmt(ip_info, " %s", REG_StringShort(reg).c_str());
      }

      // write registers:  
      for (unsigned int r = 0; r < INS_MaxNumWRegs(ins); r++) {
        if (!r) append_fmt(ip_info, SEPARATOR"write:");
        REG reg = INS_RegW(ins, r);
        append_fmt(ip_info, " %s", REG_StringShort(reg).c_str());
      }
          
      append_fmt(ip_info, SEPARATOR"fallthrough: %d", INS_HasFallThrough(ins) ? 1 : 0);
      append_fmt(ip_info, SEPARATOR"branch-or-call: %d", INS_IsBranchOrCall(ins) ? 1 : 0);
      append_fmt(ip_info, SEPARATOR"return: %d", INS_IsRet(ins) ? 1 : 0);

      // possible commands for fault injection:
      append_fmt(ip_info, SEPARATOR"cmd:");
      for (unsigned int i = (NONE+1); i < COUNT_CMD_T; i++) {
        if (cmd_possible(ins, (cmd_t)i)) append_fmt(ip_info, " %s", cmd_names[i]);
      }

      INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)instruction_info,
                     IARG_CONTEXT,
                     IARG_THREAD_ID,
                     IARG_INST_PTR,
                     IARG_END);

    }
    RTN_Close(foo);
  }
}

static VOID
instrument_injection(IMG img, VOID* v) {
  for (UINT32 i = 0; i < func.size(); ++i) {
    RTN foo = RTN_FindByName(img, func[i].c_str());
    if (!RTN_Valid(foo))
      continue;
    
    RTN_Open(foo);
    for (INS ins = RTN_InsHead(foo); INS_Valid(ins); ins = INS_Next(ins)) {
      ADDRINT ip = INS_Address(ins);

      if (ip == tip) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)count_ip,
                       IARG_THREAD_ID,
                       IARG_END);

        switch (cmd) {
        case CF:
            instrument_cf(ins, 0);
            break;
        case WADDR: /* fall through */
        case WVAL:  /* fall through */
        case RADDR: /* fall through */
        case RVAL:  /* fall through */
            instrument_addr(ins, 0);
            break;
        case RREG:
            instrument_rreg(ins, 0);
            break;
        case WREG:
            instrument_wreg(ins, 0);
            break;
        case TXT:
            instrument_txt(ins, 0);
            break;
        case NONE:
            break; // nothing to be done
        default:
            DIE("FATAL: Invalid command");
        }
      }
      // Instrumentation for detaching Pin is done last. This ensures
      // that a fault that is injected at the last instruction before
      // detaching can take effect:
      if (detach && (ip == dip)) {
        if (INS_HasFallThrough(ins)) {
          INS_InsertIfCall(ins, IPOINT_AFTER, (AFUNPTR)count_dip,
                           IARG_THREAD_ID,
                           IARG_END);
          INS_InsertThenCall(ins, IPOINT_AFTER, (AFUNPTR)inject_detach,
                             IARG_THREAD_ID,
                             IARG_CONTEXT,
                             IARG_END);
        }
        if (INS_IsBranchOrCall(ins) || INS_IsRet(ins)) {
          INS_InsertIfCall(ins, IPOINT_TAKEN_BRANCH, (AFUNPTR)count_dip,
                           IARG_THREAD_ID,
                           IARG_END);
          INS_InsertThenCall(ins, IPOINT_TAKEN_BRANCH, (AFUNPTR)inject_detach,
                             IARG_THREAD_ID,
                             IARG_CONTEXT,
                             IARG_END);

        }
      }
    }
    RTN_Close(foo);
  }
}

/* ----------------------------------------------------------------------------
 * knobs
 * ------------------------------------------------------------------------- */

KNOB<string> KnobLogFile(
    KNOB_MODE_WRITEONCE, "pintool",
    "log", "NONE",
    "bfi output file");

KNOB<string> KnobCmd(
    KNOB_MODE_WRITEONCE, "pintool",
    "cmd", "NONE",
    "command to execute (NONE|CF|RVAL|WVAL|RADDR|WADDR|RREG|WREG|TXT)");

KNOB<BOOL> KnobInfo(
    KNOB_MODE_WRITEONCE, "pintool",
    "info", "0",
    "extract information for functions of interest");

KNOB<string> KnobMethods(
    KNOB_MODE_APPEND, "pintool",
    "m", "",
    "functions for fault injection"
    "(multiple functions possible)");

KNOB<UINT64> KnobIP(
    KNOB_MODE_APPEND, "pintool",
    "ip", "",
    "target IP");

KNOB<UINT64> KnobIT(
    KNOB_MODE_APPEND, "pintool",
    "it", "",
    "iteration at target IP");

KNOB<UINT64> KnobThread(
    KNOB_MODE_WRITEONCE, "pintool",
    "thread", "0",
    "target thread (default 0)");

KNOB<BOOL> KnobDetach(
    KNOB_MODE_WRITEONCE, "pintool",
    "detach", "0",
    "detach PIN after injection (default 0)");

KNOB<UINT64> KnobDIP(
    KNOB_MODE_APPEND, "pintool",
    "dip", "",
    "detach IP");

KNOB<UINT64> KnobDIT(
    KNOB_MODE_APPEND, "pintool",
    "dit", "",
    "iteration at detachIP");

KNOB<UINT64> KnobSeed(
    KNOB_MODE_WRITEONCE, "pintool",
    "seed", "0xDEADBEEF",
    "seed to randomly select registers");

KNOB<UINT64> KnobMask(
    KNOB_MODE_WRITEONCE, "pintool",
    "mask", "0x01",
    "mask used to flip bits upon fault");

KNOB<UINT64> KnobSel(
    KNOB_MODE_WRITEONCE, "pintool",
    "sel", "-1",
    "selector of registers (default '-1' means random selection)");

/* ----------------------------------------------------------------------------
 * fini
 * ------------------------------------------------------------------------- */

VOID
fini(INT32 code, VOID *v)
{
    if (log_file) {
        fprintf(log_file, "**********************\n");
        fprintf(log_file, "COMMAND = %s\n",     KnobCmd.Value().c_str());
        fprintf(log_file, "SEL     = %d\n",     sel);
        fprintf(log_file, "SEED    = %d\n",     iseed);
        fprintf(log_file, "MASK    = 0x%llx\n", (ULLONG) mask);
        fprintf(log_file, "THREAD  = %u\n",     thread);
        fprintf(log_file, "ELAPSED = %.2fs\n",  (now() - start_ts));
        fclose(log_file);
    } else {
        fprintf(stderr, "**********************\n");
        fprintf(stderr, "COMMAND = %s\n",     KnobCmd.Value().c_str());
        fprintf(stderr, "SEL     = %d\n",     sel);
        fprintf(stderr, "SEED    = %d\n",     iseed);
        fprintf(stderr, "MASK    = 0x%llx\n", (ULLONG) mask);
        fprintf(stderr, "THREAD  = %u\n",     thread);
        fprintf(stderr, "ELAPSED = %.2fs\n",  (now() - start_ts));
    }
}

/* ----------------------------------------------------------------------------
 * helper message and main
 * ------------------------------------------------------------------------- */

static INT32
usage()
{
    fprintf(stderr, "BFI: bit-flip injector\n");
    fprintf(stderr, "%s", KNOB_BASE::StringKnobSummary().c_str());
    return -1;
}

int
main(int argc, char * argv[])
{
    PIN_InitSymbols();

    // parse command line and get knob values
    if (PIN_Init(argc, argv)) return usage();
    if (KnobLogFile.Value().compare("NONE") != 0) {
        log_file = fopen(KnobLogFile.Value().c_str(), "w+");
    }

    detach  = KnobDetach.Value();
    thread  = KnobThread.Value();
    sel     = KnobSel.Value();
    seed    = KnobSeed.Value();
    iseed   = seed; // save that for later
    mask    = KnobMask.Value();
    cmd     = cmd_select(KnobCmd.Value().c_str());
    for (UINT32 i = 0; i < KnobMethods.NumberOfValues(); ++i) {
        func.push_back(KnobMethods.Value(i));
    }
    tip = KnobIP.Value();
    tit = KnobIT.Value();
    dip = KnobDIP.Value();
    dit = KnobDIT.Value();

    // XXX: add thread initializtion. If multiple threads created warn
    // the user to use the -thread knob.

    // add function monitors if -m knob set at least once
    if (KnobInfo.Value()) {
      IMG_AddInstrumentFunction(extract_info, 0);
    }
    
    if (cmd != NONE) {
      IMG_AddInstrumentFunction(instrument_injection, 0);
    }

#ifdef DISASM
    // add trigger counting based on the trigger type -ttype
    INS_AddInstrumentFunction(instrument_disasm, 0);
#endif /* DISASM */

    // register the cleanup function
    PIN_AddFiniFunction(fini, 0);

    // save time
    start_ts = now();

    // start program passed to pin tool after --
    PIN_StartProgram();
    return 0;
}

