# BFI: bit-flip injector

BFI is a simple plugin for the Intel's Pin dynamic binary instrumentation tool.
BFI injects faults in a running program by bit-flipping registers, memory
locations.  The general command is:

```
pin -t bfi.so [options] -- program_under_test
```

## BFI overview 

In a program execution, BFI injects one single fault before or after the
execution of a given instruction.  This instruction is called the *trigger*. 
At the trigger instruction, a register or a memory location is selected
depending on the *fault type* given as option.

BFI supports the following fault types:

- CF   : change instruction pointer (control-flow).
- WVAL : some address that is written is overwritten with an arbitrary value.
- RVAL : some address that is read is written with an arbitrary value
         before being read.
- WADDR: some pointer that is written is corrupted (value is correct).
- RADDR: some pointer that is read is corrupted.
- RREG : some register that is read is overwritten with an arbitrary value
         before being read.
- WREG : some register that is written is overwritten with an arbitrary value
         after being written.
- TXT  : change the opcode of an instruction before executing it.

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

## Further functionality

During the execution of a program, it might be useful to know if the fault is
injected within the scope of a function or not.  The knob `-m FUNC` can be used
to register one or multiple functions (e.g., `-m malloc -m free`).  BFI prints
information when entering or leaving the registered functions, in particular
the trigger counters.

BFI supports multi-threading programs.  However, only one thread can inject
faults.  To select the "faulty" thread use the `-thread THREAD` knob (by
default thread 0 is selected).

## Requirements and Compilation

You'll need:

- Pin (http://pintool.org/)
- gcc

Either pass `PIN_ROOT` as argument to `make`

```
make PIN_ROOT=/path/to/pin/uncompressed/zip
```

or create a `Makefile.local` file with the line:

```
PIN_ROOT=/path/to/pin/uncompressed/zip
```

## Usage Examples

General command is:

```
pin -t bfi.so [options] -- program_under_test
```

### Get general information without any fault injections

```
pin -t bfi.so -log mylogfile -- ls
```

This command runs *ls* and saves general information (total amount of instructions executed, amount of time used) in *log.log*.

### List all supported knobs (command-line arguments)

```
pin -t bfi.so -h -- ls
```

### List all invocations of function `foobar`

```
pin -t bfi.so -m foobar -- ./myprogram -arg1 hello -arg2 world
```

This command lists all entrance and leave points for function *foobar* in program *myprogram* (which accepts arguments *arg1* and *arg2*). Sample output:

```
[.:    0, IP = 0x400780, i = 89277, wa = 0, ra = 0, rr = 0, wr = 0, it = 0, t = 0]
	enter foobar iteration = 2
[.:    0, IP = 0x40079a, i = 89280, wa = 0, ra = 0, rr = 0, wr = 0, it = 0, t = 0]
	leave foobar
```

indicates that function range is 0x400780 - 0x40079a, this is the second invocation of the function and it is executed on instructions 89277 - 89280.

### Get information about the instruction

```
pin -t bfi.so -cmd FIND -trigger 89279 -- ./myprogram
```

The command provides one with information about actions on instruction 89279. Sample output:

```
[.:    0, IP = 0x400783, i = 89279, wa = 0, ra = 0, rr = 0, wr = 0, it = 0, t = 0]
	raddr = 0, waddr = 0, rreg = 2, wreg = 1
```

informs that the instruction reads two registers and writes into one register; there are no memory reads/writes.

### Inject fault at instruction

```
pin -t bfi.so -cmd WREG -trigger 89279 -- ./myprogram
```

The command injects one bit-flip into register that was written into (WREG fault). Sample output:

```
[.:    0, IP = 0x400798, i = 89280, wa = 0, ra = 0, rr = 0, wr = 0, it = 0, t = 0]
	at ip 0x40079a, eax = 0x3039, eax' = 0x3038
```

Here register *eax* was corrupted at instruction 89280. Notice that the fault was injected not at 89279 instruction as we requested: BFI injects the fault at the first suitable instruction *on or after* the requested instruction.

### Information about function invocations and fault injections can be combined

```
pin -f bfi.so -m foobar -cmd WREG -trigger 89279 -- ./myprogram
```

This lists all invocations of *foobar* and also injects a WREG fault.

### Inject at instruction address (not at *instruction number* as in previous examples)

```
pin -t bfi.so -cmd WREG -ip 0x40079a -trigger 2 -ttype IT -- ./myprogram
```

This command injects the fault when the instruction on address 0x40079a is executed for the second time.

### Corrupt several bits (not *the lowest bit* as in previous examples)

```
pin -t bfi.so -cmd WREG -mask 0xFF -ip 0x40079a -trigger 2 -ttype IT -- ./myprogram
```

This will bit-flip 8 lowest bits; sample output:

```
[.:    0, IP = 0x400798, i = 89280, wa = 0, ra = 0, rr = 0, wr = 0, it = 0, t = 0]
	at ip 0x40079a, eax = 0x3039, eax' = 0x30c6
```

### Starting BFI breakpointing after fault inside gdb

Start Pin with the `-appdebug` option:

```
pin -appdebug -t bfi.so [options] -- ./program
```

You should get an output such as:
```
Application stopped until continued from debugger.
Start GDB, then issue this command at the (gdb) prompt:
  target remote :60940
```

Now start gdb with `program` as file:
```
gdb ./program
```

And connect to pin issuing the command `target remote :60940`.