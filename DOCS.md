# <span style="color:red">This document is subject to change at any time.</span>

# VM Debugger Configuration Guide

This guide describes how to prepare the three artifacts that the `vmdbg` GDB
plugin expects before you can debug a virtual machine: `vm_isa.yml`,
`vmdbg_config.yml`, and a disassembly listing. The instructions cover both
stack-oriented virtual machines (where state lives inside a struct) and
register-file designs (where registers are stored in contiguous memory).

---

## 1. Defining the ISA (`vm_isa.yml`)

Every VM needs a YAML file that lists the instruction set and register naming
scheme. The schema is flexible enough to describe both stack machines and
register machines.

### 1.1 Global Fields

| Key | Purpose | Example |
| --- | --- | --- |
| `vm_name` | Human-readable identifier | `my_vm` |
| `byte_order` | Encodings used in bytecode (`little` / `big`) | `little` |
| `fields_order` | Ordered list of bytecode fields for operands | Stack VMs often use `["opcode","data"]`; hybrid/register VMs may use items such as `["arg1","opcode","arg2"]` |

### 1.2 Registers Section

- Stack VMs can leave `registers` empty when all state is implicitly on the data
  stack.
- Register-file VMs map encoded register identifiers to friendly names. The
  keys (e.g., `"0x20"`, `"0x04"`) should match the values stored in bytecode,
  while the values (`a`, `b`, `c`, …) are the names that debugger commands will
  display.

### 1.3 Instructions Section

Each opcode entry is indexed by its hexadecimal value as a string, and includes:

- `mnemonic`: name shown in disassembly (`"PUSH_CONST"`, `"IMM"`, …).
- `length`: total byte/word length for the instruction encoding.
- `operands`: optional list of operand descriptors, where each operand defines:
  - `name`: label used in disassembly.
  - `kind`: operand type (`imm` (immediate value), `reg` (register), `reg_or_imm`, etc.).
  - `source`: field from `fields_order` to read the encoded value.
  - `optional` (bool): mark operands that may be absent depending on flag bits
    or encoding variants.
- `semantics` / `note`: free-form text explaining what the instruction does.

Stack VM example:

```yaml
"0x07":
  mnemonic: "ADD"
  length: 1
  operands: []
  semantics: "pop b, pop a, push a + b"
```

Register VM example:

```yaml
"0x02":
  mnemonic: "IMM"
  length: 3
  operands:
    - { name: "dst", kind: "reg", source: "arg1" }
    - { name: "src", kind: "imm", source: "arg2" }
  semantics: "arg1 = arg2"
```

**Checklist**
1. Enumerate every opcode you expect the bytecode to hit.
2. Ensure operand descriptors refer to fields defined in `fields_order`.
3. Keep register names consistent with what you plan to expose in runtime config.

---

## 2. Writing `vmdbg_config.yml`

This file binds the abstract ISA to the concrete runtime layout used by GDB.
All paths are typically relative to the VM-specific directory.

### 2.1 ISA and Bytecode Sections

```yaml
isa_file: "./vm_isa.yml"

bytecode:
  file: "./float_program.bin"
  base_offset: 0
  max_size: 0x70000
  entry_offset: 0
```

- `isa_file`: path to the YAML file described above.
- `bytecode.file`: raw bytecode blob in target memory/process inputs.
- `base_offset`: additional offset added when translating VM PC to bytecode
  index (non-zero if bytecode is embedded inside other data).
- `max_size`: guard against accidental out-of-bounds reads.
- `entry_offset`: index of the VM entry point (used when highlighting the first
  instruction).

Use the same structure regardless of VM style; just set the filename, bounds,
and entry offset to match your bytecode blob.

### 2.2 Runtime Dispatcher

```yaml
runtime:
  dispatcher_symbol: "interpret_vm"
  dispatcher_offset: null
```

- Prefer `dispatcher_symbol`: name of the interpreter/dispatch function GDB can
  resolve. This lets `vmdbg` set a breakpoint immediately.
- If symbols are stripped, you can supply `dispatcher_offset` instead (relative
  to the main executable base).

### 2.3 `vm_mem` Layouts

The `runtime.vm_mem` block tells `vmdbg` where the VM keeps its live state. Two
approaches are supported:

#### 2.3.1 Struct-based Stack VM

When the interpreter exposes a global struct containing VM state, the config can
reference symbolic fields:

- `vm_stack: true` enables stack-aware helpers such as `vm-callstack`.
- `vm_vmmap: true` allows `vm-vmmap` to enumerate VM memory regions.
- Each sub-block (`vm_state`, `bytecode`, `pc`, `stack`, `memory`, `callstack`)
  defines:
  - `symbol`: name of the global struct (`vm_state`).
  - For aggregate sections: `ptr_field`, `size_field`, `depth_field`, etc.,
    which should match the struct members defined in the VM source.
  - `in_vm_vmmap`: whether that region should appear in `vm-vmmap`.
- Example snippet:

```yaml
vm_state:
  symbol: "vm_state"
  in_vm_vmmap: true

pc:
  field: "program_count"
  in_vm_vmmap: true

stack:
  ptr_field: "stack"
  size_field: "stack_size"
  depth_field: "stack_depth"
  in_vm_vmmap: true
```

With this information, vmdbg can call `gdb.parse_and_eval` on expressions such
as `vm_state.program_count`, automatically computing VM PC indices and stack
addresses.

#### 2.3.2 Register-file VM

Register-based interpreters often store VM state in a memory blob pointed to by
one of the host registers. The config therefore uses fixed offsets:

```yaml
vm_mem:
  vm_stack: false
  base_register: "rdi"
  regs_base_offset: 1024
  pc_reg: "i"
```

- `base_register`: host CPU register that holds the base address of VM memory
  (set by the interpreter).
- `regs_base_offset`: byte offset from `vm_base` to the register file blob.
- `pc_reg`: **ISA register name** that should be treated as the VM program
  counter; vmdbg will read it from the register file.
- Optional extras include `pc_offset`, `sp_offset`, `memory.ptr_offset`, etc.,
  when you track PC/stack pointers by raw offsets instead of struct fields.

### 2.4 Enabling Additional Features

- `vm_breakpoints` (stored in runtime state) become usable once either PC field
  or register is configured.
- `vm_vmmap: true` allows `vm-vmmap` to display bytecode, stack, general memory,
  and callstack regions if corresponding blocks specify `in_vm_vmmap: true`.
- To expose custom sections, mimic the `stack`, `memory`, and `callstack`
  sub-blocks: provide pointer/size/depth metadata pointing to either struct
  fields or offsets (with `ptr_offset`, `size_offset`, etc.).

---

## 3. Preparing the Disassembly File

The `disasm` block in `vmdbg_config.yml` ties everything together:

```yaml
disasm:
  file: "./disasm_vm.txt"
```

Requirements:

1. The file must exist on disk when vmdbg is sourced, typically next to the
   config.
2. Each line should correspond to one VM instruction in bytecode order. The
   plugin uses the current dispatcher hit count (or `pc_reg`) as an index into
   this list, so the nth line should describe the nth instruction.
3. Include enough context per line (mnemonic, operands, comments) to orient
   yourself during debugging, e.g., `0008: ADD           ; pop b, pop a`.
4. Update the file whenever you regenerate bytecode. 

Once set, you can run `vm-disasm` inside GDB. If vmdbg knows the current VM PC,
it highlights that line; otherwise it prints the full file.

---

## 4. Putting It All Together

1. Create a workspace directory for your VM artifacts.
2. Fill out `vm_isa.yml` with your opcode semantics and register naming.
3. Update `vmdbg_config.yml`:
   - Point `isa_file` and `bytecode.file` at your artifacts.
   - Configure `runtime.dispatcher_*` to match the interpreter entry point.
   - Describe VM memory layout using either struct fields or offsets.
   - Reference your disassembly listing under `disasm.file`.
4. Generate `disasm_*.txt` so that each line is an instruction in execution
   order.
5. Launch your VM under GDB, source `test_vmdbg.py`, and use the plugin
   commands (`vm-disasm`, `vm-regs`, `vm-mem`, `vm-vmmap`, …).

Following these steps ensures vmdbg has enough metadata to watch the dispatcher,
show VM-aware disassembly, inspect registers, and dump VM memory—regardless of
whether the VM uses stacks, registers, or a hybrid memory layout.
