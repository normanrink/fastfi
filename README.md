# FastFI: fast fault injector

FastFI is a plug-in for [Intel's Pin Tool](https://software.intel.com/en-us/articles/pin-a-dynamic-binary-instrumentation-tool) which implements fault injection into a running program.
FastFI is derived from the [BFI bit-flip injector](https://bitbucket.org/db7/bfi), and so is this readme file.
Please also refer to BFI's documentation.
The key motivation of developing FastFI was to improve the runtime of fault-injection experiments while retaining fine-grain control over injected fault.


## Getting started

To build the FastFI plug-in, simply run `make` in the source directory.
The `make` command requires that the environment variable `PIN_ROOT` be set to the directory where the Pin Tool's executable lives.
After successfully building the plug-in, the Pin Tool can be run as follows: 

  `pin -t fastfi.so [options] -- test_program`

When the list of `[options]` is empty, the plug-in will not do anything.
Most importantly, no faults will be injected.
The above command will simply produce a short log on the terminal.
This behaviour is inherited from BFI.


## Overview

Like the BFI plug-in, FastFI injects a single fault before or after the execution of a given instruction _Ins_.
A fault is injected by flipping bits in one of the following locations:

  - registers
  - memory
  - address bus
  - instruction opcodes

The following kinds of faults (_commands_ in BFI's terminology) map to the above locations:

  - `CF`: a _control-flow_ fault is modelled by flipping bits in the instruction pointer (i.e. the `eip`/`rip` register) before _Ins_ is executed.
  - `RREG`: bit-flips in a register before the register's value is read _Ins_.
  - `WREG`: bit-flips in a register after the register's value has been written by _Ins_.
  - `RVAL`: bit-flips in a memory location before the location's value is read by _Ins_.
  - `WVAL`: bit-flips in a memory location after the location's value has been written by _Ins_.
  - `RADDR`: bit-flips in an address on the address bus before _Ins_ reads from the address.
  - `WADDR`: bit-flips in an address on the address bus before _Ins_ writes to the address.
  - `TXT`: bit-flips in the instruction opcoe of _Ins_.

A typical fault injection command will look like this:

  `pin -t fastfi.so -m test_function -ip 0x400751 -it 1 -cmd CF -mask 0x1 -- test_program`

This will inject a control-flow fault immediately before the instruction at address `0x400751` is executed.
Bits in the instruction pointer are flipped by xor-ing the argument of `-mask` into the instruction pointer.
Since `0x400751 ^ 0x1 = 0x400750`, the injected fault will cause execution of the opcode at `0x400750` instead of _Ins_.

As another example, let's look at injecting a fault into one of _Ins_'s input registers:

  `pin -t fastfi.so -m test_function -ip 0x400750 -it 1 -cmd RREG -mask 0x1 -- test_program`

This will xor the mask '0x1' into one of the first of _Ins_'s input registers.
If _Ins_ reads from more than one register, one can select the register for fault injection with the `-sel` command line option, e.g.

  `pin -t fastfi.so -m test_function -ip 0x400750 -it 1 -cmd RREG -sel 1 -mask 0x1 -- test_program`

will inject into the second of _Ins_'s input register.
Alternatively, if the option `-seed` is given, a register will be chosen randomly, e.g.

  `pin -t fastfi.so -m test_function -ip 0x400750 -it 1 -cmd RREG -seed 0xdeadbeef -mask 0x1 -- test_program`

The possible command line options of FastFI are discussed in more detail in the next section.


## Typical FastFI workflow 

FastFI is designed to study the response of individual functions to faults.
Hence the function of interest must be specified as one of the command line `[options]`:

  `pin -t fastfi.so -m test_function -- test_program`

Multiple functions can be speficied on the command line.
Each of the function names must be preceded by the `-m` option.
An annotated listing of assembly instructions which are executed by the `test_function` can be obtained by also specifying `-info` on the command line:

  `pin -t fastfi.so -m test_function -info -- test_program`

The first two lines of output may look like this:

  ```
  ip: 0x400750 -- iteration: 1 -- assembly: push rbp -- read: rbp rsp -- write: rsp -- fallthrough: 1 -- branch-or-call: 0 -- return: 0 -- cmd: CF WVAL WADDR RREG WREG TXT
  ip: 0x400751 -- iteration: 1 -- assembly: mov rbp, rsp -- read: rsp -- write: rbp -- fallthrough: 1 -- branch-or-call: 0 -- return: 0 -- cmd: CF RREG WREG TXT
  ```

Each line is a list of key-value pairs corresponding to one assembly instruction.
Key-value pairs separated by `--`, and keys are separated from values by a colon `:`.
The meanings of values are as follows:

  1. `ip`: The address of the assembly instruction (viz. _instruction poiner_).
  
  2. `interation`: The number of times this instruction has already been executed.

  3. `assembly`: The assembly code of the current instruction.

  4. `read`: A space-separated list of registers read by the current instruction.
     (Note that this includes implicit reads such as reading the stack pointer `rsp` during a `push` instruction.)

  5. `write`: A space-separated list of registers written by the current instruction.
     (Note that this includes implicit writes such as writing the stack pointer `rsp` during a `push` instruction.)

  6. `fallthrough`: A flag indicating whether the current instruction has a fall-through control path.
     Typical instructions without a fall-through path are unconditional jumps and returns.

  7. `branch-or-call`: A flag which indicates whether the current instruction is either a branch or function call.

  8. `return`: A flag which indicates whether the current instruction is a return instruction.

  9. `cmd`: A space-separated list of kinds of faults which can be injected at the current instruction.

For operating the FastFI plug-in only the values of the keys `ip`, `iteration`, and `cmd` are relevant.
The remaining key-value pairs are useful for debugging.


To inject a fault into a running program, FastFI must be given a list of `[options]` which specify the location and kind of the fault which is to be injected.


The command is valid only if the instruction address is inside the function `test_function`.

the address of an instruction where the fault is to be injected.
Henceforth we refer to this address as the `ip` (for _instruction pointer_).
Since the same `ip` may be visited multiple times during program execution, FastFI further requires an _iteration_ to uniquely identify the dynamic instruction at which the fault is to be injected.
If the instruction at address `ip` is executed _n_ times, then the iteration must be an integer _k_ such that 1 <= _k_ <= n.
The fault is then injected when the instruction at `ip` is executed for the _k_-th time.


Besides injecting faults, BFI can perform other *commands* when at a trigger
instruction, for example, it migh simply to print the trigger address and
source-code information such as file and line number.  To select a fault type
or another command, use the command knob, e.g., `-cmd CF` injects a
control-flow fault.

The command knob supports the fault types above and the following further
commands:

- NONE : prints the summary at the end of the execution (default). 
- FIND : shows information for a given trigger instruction.

Trigger instructions can be selected in several ways.  The default selection
is by counting the number of executed instructions and setting the N-th
executed instruction to be the trigger using `-trigger N`.

As concrete example, to inject a control-flow fault in `ls` at the 10000th
exectued instruction, type:

```
pin -t bfi.so -trigger 10000 -cmd CF -- ls
```

Some commands cannot be executed at some instructions, for example, if an
instructions does not read from memory, no fault can corrupt a memory location
at that instruction.  The trigger is then the first instruction after the N-th
executed instruction at which the command can be executed.

A specific instruction in the code can be selected with the `-ip IP` knob. In
this case, BFI executes the desired command at the first occurrence of IP
after the N-th executed instruction. (See examples below.)

BFI supports other forms of counting for selecting the trigger via the trigger
type knob `-ttype TRIGGER_TYPE`.  Besides the basic instruction counting,
another useful trigger type is the iteration counting `IT`, which is to be
used in conjunction with `-ip`.  If the trigger is selected with iteration
counting, the N-th execution of IP is the trigger for the command.  The
complete sequence of parameters is 

```
pin -t bfi.so -trigger N -ttype IT -ip IP -- program
```

The complete list of trigger types follows.

- IN : counts the number of executed instructions (default).
- RA : counts the number of read addresses. If an instruction reads from
       multiple addresses, they are all counted.
- WA : counts the number of written addresses. If an instruction writes to
       multiple addresses, they are all counted.
- RR : counts the number of read registers. (multiple per instr.)
- WR : counts the number of written registers. (may be multiple per instr.)
- IT : counts the number of iterations the instruction pointer contains a
       given value (via `-ip`).


### List all supported knobs (command-line arguments)

```
pin -t bfi.so -h -- ls
```


### Debugging test programs under the control of FastFI (from BFI documentation)

Start the Pin Tool with the `-appdebug` option:

  `pin -appdebug -t fastfi.so [options] -- test_program`

You should get an output such as:

  ```
  Application stopped until continued from debugger.
  Start GDB, then issue this command at the (gdb) prompt:
    target remote :60940
  ```

Now start gdb with `test_program` as file:

  `gdb test_program`

Connect to the running instance of Pin by issuing the command `target remote :60940`.
For more details, please refer to the [Pin documentation](https://software.intel.com/sites/landingpage/pintool/docs/76991/Pin/html/index.html#APPDEBUG).


## Bug reports and suggestion

Should you need to debug the FastFI plug-in itself (rather than a test program running under Pin's/FastFI's control), please also refer to the [Pin documentation](https://software.intel.com/sites/landingpage/pintool/docs/76991/Pin/html/index.html#DEBUGGING).
Alternatively, send a bug report to norman.rink@tu-dresden.de.

Suggestions for further development and improvement should also be submitted to norman.rink@tu-dresden.de.


