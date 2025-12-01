# vmdbg.py
import gdb # type: ignore
import yaml
import os
import struct

_vm_config = None
_vm_state = {
    "step": 0,        
    "vm_base": None,  
    "pc_index": None, 
    "vm_breakpoints": set(),   
}


def load_config(path="vmdbg_config.yml"):
    global _vm_config
    if _vm_config is not None:
        return _vm_config

    if not os.path.exists(path):
        gdb.write(f"[-] vmdbg: config file not found: {path}\n", gdb.STDERR)
        _vm_config = {}
        return _vm_config

    with open(path, "r", encoding="utf-8") as f:
        _vm_config = yaml.safe_load(f) or {}
    return _vm_config

def load_isa_register_order():
    
    cfg = load_config()
    isa_path = cfg.get("isa_file", "./vm_isa.yml")

    if not os.path.exists(isa_path):
        gdb.write(f"[-] vmdbg: ISA file not found: {isa_path}\n", gdb.STDERR)
        return []

    with open(isa_path, "r", encoding="utf-8") as f:
        isa = yaml.safe_load(f) or {}

    reg_map = isa.get("registers", {})

    names_in_file = list(reg_map.values())

    preferred = ["a", "b", "c", "d", "s", "i", "f"]
    ordered = [r for r in preferred if r in names_in_file]

    extras = sorted(r for r in names_in_file if r not in ordered)
    return ordered + extras

def read_vm_reg_byte(vm_base, reg_name):
    
    cfg = load_config()
    runtime_cfg = cfg.get("runtime", {})
    vm_mem_cfg = runtime_cfg.get("vm_mem", {})

    regs_base_offset = vm_mem_cfg.get("regs_base_offset")
    if regs_base_offset is None:
        gdb.write("[-] vmdbg: vm_mem.regs_base_offset not configured\n", gdb.STDERR)
        return None

    reg_names = load_isa_register_order()
    if reg_name not in reg_names:
        gdb.write(f"[-] vmdbg: register {reg_name!r} not found in ISA\n", gdb.STDERR)
        return None

    idx = reg_names.index(reg_name)
    addr = vm_base + regs_base_offset + idx

    inferior = gdb.selected_inferior()
    try:
        mem = inferior.read_memory(addr, 1)
        return bytes(mem)[0]
    except gdb.MemoryError as e:
        gdb.write(f"[-] vmdbg: failed to read {reg_name} at 0x{addr:x}: {e}\n", gdb.STDERR)
        return None

def _parse_dump_flags(arg, default_count=20, default_unit="g", default_fmt="x"):
   
    arg = (arg or "").strip()
    if not arg or not arg.startswith("/"):
        return default_count, default_unit, default_fmt

    spec = arg[1:].strip().split()[0] if len(arg) > 1 else ""
    units = {"b": 1, "h": 2, "w": 4, "g": 8}
    formats = {"x", "d", "u", "f", "c"}

    count_str = ""
    unit = None
    fmt = None

    for ch in spec:
        if ch.isdigit() and unit is None and fmt is None:
            count_str += ch
        elif ch in units and unit is None:
            unit = ch
        elif ch in formats and fmt is None:
            fmt = ch
        else:
            continue

    try:
        count = int(count_str) if count_str else default_count
        if count <= 0:
            count = default_count
    except ValueError:
        count = default_count

    if unit is None:
        unit = default_unit
    if fmt is None:
        fmt = default_fmt

    return count, unit, fmt

def _dump_vm_memory(start_addr, count, unit, fmt):
    
    unit_sizes = {"b": 1, "h": 2, "w": 4, "g": 8}
    if unit not in unit_sizes:
        unit = "g"
    size = unit_sizes[unit]

    inferior = gdb.selected_inferior()

    line_bytes = 16
    per_line = max(1, line_bytes // size)

    unsigned_fmt = {1: "<B", 2: "<H", 4: "<I", 8: "<Q"}
    signed_fmt = {1: "<b", 2: "<h", 4: "<i", 8: "<q"}
    float_fmt = {4: "<f", 8: "<d"}

    for i in range(0, count, per_line):
        line_addr = start_addr + i * size
        gdb.write(f"0x{line_addr:016x}: ")

        vals = []
        for j in range(per_line):
            idx = i + j
            if idx >= count:
                break

            addr = line_addr + j * size
            try:
                mem = inferior.read_memory(addr, size)
                raw = bytes(mem)
            except gdb.MemoryError:
                vals.append("<memerr>")
                continue

            if fmt == "x":
                try:
                    (val_u,) = struct.unpack(unsigned_fmt[size], raw)
                    width = size * 2
                    vals.append(f"0x{val_u:0{width}x}")
                except struct.error:
                    vals.append("<err>")
            elif fmt == "d":
                try:
                    (val_s,) = struct.unpack(signed_fmt[size], raw)
                    vals.append(f"{val_s}")
                except struct.error:
                    vals.append("<err>")
            elif fmt == "u":
                try:
                    (val_u,) = struct.unpack(unsigned_fmt[size], raw)
                    vals.append(f"{val_u}")
                except struct.error:
                    vals.append("<err>")
            elif fmt == "f" and size in float_fmt:
                try:
                    (val_f,) = struct.unpack(float_fmt[size], raw)
                    vals.append(f"{val_f!r}")
                except struct.error:
                    vals.append("<err>")
            elif fmt == "c" and size == 1:
                ch = raw[0]
                if 32 <= ch <= 126:
                    vals.append(f"'{chr(ch)}'")
                else:
                    vals.append(f"'\\x{ch:02x}'")
            else:
                try:
                    (val_u,) = struct.unpack(unsigned_fmt[size], raw)
                    width = size * 2
                    vals.append(f"0x{val_u:0{width}x}")
                except struct.error:
                    vals.append("<err>")

        gdb.write("  ".join(vals) + "\n")

class VmDispatcherBreakpoint(gdb.Breakpoint):
    def __init__(self, config_path="vmdbg_config.yml"):
        self.config_path = config_path

        spec = self._get_dispatcher_spec()
        if spec is None:
            gdb.write("[-] vmdbg: dispatcher not configured; no breakpoint set.\n")
            self.valid = False
            return

        try:
            super().__init__(spec, gdb.BP_BREAKPOINT, internal=False)
            self.silent = True
            self.valid = True
            gdb.write(f"[+] vmdbg: dispatcher breakpoint set on {spec}\n")
        except gdb.error as e:
            gdb.write(f"[-] vmdbg: failed to set dispatcher breakpoint: {e}\n", gdb.STDERR)
            self.valid = False

    def _get_dispatcher_spec(self):
        cfg = load_config(self.config_path)
        runtime_cfg = cfg.get("runtime", {})

        sym = runtime_cfg.get("dispatcher_symbol")
        if sym:
            return sym

        disp_off = runtime_cfg.get("dispatcher_offset")
        if disp_off is None:
            return None

        try:
            off = int(str(disp_off), 0)  
        except ValueError:
            gdb.write(f"[-] vmdbg: invalid dispatcher_offset {disp_off!r}\n", gdb.STDERR)
            return None

        base = self._get_pie_base()
        if base is None:
            gdb.write("[-] vmdbg: cannot use dispatcher_offset without PIE base\n", gdb.STDERR)
            return None

        addr = base + off
        return f"*0x{addr:x}"

    def _get_pie_base(self):
        
        exe = None
        try:
            info_files = gdb.execute("info files", to_string=True)
        except gdb.error as e:
            gdb.write(f"[-] vmdbg: 'info files' failed: {e}\n", gdb.STDERR)
            return None

        for line in info_files.splitlines():
            line = line.strip()
            if line.startswith("Symbols from"):
                parts = line.split('"')
                if len(parts) >= 2:
                    exe = parts[1]
                    break
            if "Local exec file:" in line:
                after = line.split("Local exec file:")[-1].strip()
                after = after.strip("`' ")
                if after:
                    exe = after.split(",")[0].strip()
                    break

        if not exe:
            gdb.write("[-] vmdbg: could not determine executable path from 'info files'\n", gdb.STDERR)
            return None

        try:
            maps = gdb.execute("info proc mappings", to_string=True)
        except gdb.error as e:
            gdb.write(f"[-] vmdbg: 'info proc mappings' failed: {e}\n", gdb.STDERR)
            return None

        base = None
        for line in maps.splitlines():
            if exe in line:
                parts = line.split()
                if not parts:
                    continue
                try:
                    base = int(parts[0], 16)
                    break
                except ValueError:
                    continue

        if base is None:
            gdb.write(f"[-] vmdbg: could not find mapping for {exe} in 'info proc mappings'\n", gdb.STDERR)
        return base

    def stop(self):
        cfg = load_config(self.config_path)
        runtime_cfg = cfg.get("runtime", {})
        vm_mem_cfg = runtime_cfg.get("vm_mem", {})

        _vm_state["step"] += 1

        base_reg = vm_mem_cfg.get("base_register")
        if base_reg:
            try:
                val = gdb.parse_and_eval(f"${base_reg}")
                _vm_state["vm_base"] = int(val)
            except gdb.error as e:
                gdb.write(f"[-] vmdbg: failed to read ${base_reg}: {e}\n", gdb.STDERR)

        pc_index = None

        if vm_mem_cfg.get("vm_stack", False):
            vm_state_cfg = vm_mem_cfg.get("vm_state", {})
            pc_cfg = vm_mem_cfg.get("pc", {})

            symbol = vm_state_cfg.get("symbol")
            field = pc_cfg.get("field")

            if symbol and field:
                try:
                    pc_val = gdb.parse_and_eval(f"{symbol}.{field}")
                    pc_index = int(pc_val)
                except gdb.error as e:
                    gdb.write(f"[-] vmdbg: failed to read VM pc field {symbol}.{field}: {e}\n", gdb.STDERR)
                except (TypeError, ValueError):
                    gdb.write(f"[-] vmdbg: non-integer VM pc value from {symbol}.{field}\n", gdb.STDERR)

        if pc_index is None:
            pc_reg_name = vm_mem_cfg.get("pc_reg")
            if pc_reg_name and _vm_state.get("vm_base") is not None:
                pc_val = read_vm_reg_byte(_vm_state["vm_base"], pc_reg_name)
                if pc_val is not None:
                    pc_index = pc_val

        _vm_state["pc_index"] = pc_index

        vm_bps = _vm_state.get("vm_breakpoints") or set()

        if _vm_state.get("single_step"):
            _vm_state["single_step"] = False
            gdb.write(f"[vmdbg] vm-next hit at pc={pc_index} (step #{_vm_state['step']})\n")
            return True

        if not vm_bps:
            gdb.write(f"[vmdbg] dispatcher hit #{_vm_state['step']}")
            if pc_index is not None:
                gdb.write(f" (pc={pc_index})")
            gdb.write("\n")
            return True

        if pc_index is not None and pc_index in vm_bps:
            gdb.write(
                f"[vmdbg] vm-break hit at pc={pc_index} (step #{_vm_state['step']})\n"
            )
            return True

        return False

class ShowDisasm(gdb.Command):

    def __init__(self):
        super().__init__("vm-disasm", gdb.COMMAND_USER)
        self.disasm_path = None
        self._load_disasm_path()

    def _load_disasm_path(self):
        cfg = load_config()
        disasm_cfg = cfg.get("disasm", {})
        path = disasm_cfg.get("file")
        if not path:
            gdb.write("[-] vmdbg: disasm.file not set in vmdbg_config.yml\n", gdb.STDERR)
            return
        self.disasm_path = path

    def _parse_args(self, arg):
        
        arg = (arg or "").strip()
        if not arg:
            return 0, None

        tokens = arg.split()
        offset = 0
        count = None
        i = 0

        while i < len(tokens):
            t = tokens[i]
            if t in ("-off", "--offset"):
                if i + 1 >= len(tokens):
                    gdb.write("[-] vmdbg: -off requires an integer argument\n", gdb.STDERR)
                    break
                try:
                    offset = int(tokens[i + 1], 0)
                except ValueError:
                    gdb.write(f"[-] vmdbg: invalid offset {tokens[i+1]!r}\n", gdb.STDERR)
                i += 2
            elif t in ("-n", "--count"):
                if i + 1 >= len(tokens):
                    gdb.write("[-] vmdbg: -n requires an integer argument\n", gdb.STDERR)
                    break
                try:
                    n = int(tokens[i + 1], 0)
                    if n > 0:
                        count = n
                except ValueError:
                    gdb.write(f"[-] vmdbg: invalid count {tokens[i+1]!r}\n", gdb.STDERR)
                i += 2
            else:
                gdb.write(f"[-] vmdbg: unknown vm-disasm flag {t!r}\n", gdb.STDERR)
                i += 1

        return offset, count

    def invoke(self, arg, from_tty):
        if self.disasm_path is None:
            self._load_disasm_path()
        if not self.disasm_path:
            gdb.write("[-] vmdbg: no disasm file configured\n", gdb.STDERR)
            return

        if not os.path.exists(self.disasm_path):
            gdb.write(f"[-] vmdbg: disasm file not found: {self.disasm_path}\n", gdb.STDERR)
            return

        try:
            with open(self.disasm_path, "r", encoding="utf-8") as f:
                raw_lines = f.readlines()
        except OSError as e:
            gdb.write(f"[-] vmdbg: failed to read disasm file: {e}\n", gdb.STDERR)
            return

        lines = [line.rstrip("\n") for line in raw_lines]
        total = len(lines)

        if total == 0:
            gdb.write("[+] vmdbg: disasm file is empty\n")
            return

        pc_idx = _vm_state.get("pc_index")
        if pc_idx is not None:
            try:
                pc_idx = int(pc_idx)
            except (TypeError, ValueError):
                pc_idx = None

        if pc_idx is not None and not (0 <= pc_idx < total):
            pc_idx = None

        offset, count = self._parse_args(arg)

        if pc_idx is not None:
            base_idx = pc_idx + offset
            if base_idx < 0:
                base_idx = 0
            if base_idx >= total:
                base_idx = total - 1

            if count is not None:
                start_idx = base_idx
                end_idx = min(total, base_idx + count)
            else:
                start_idx = max(0, base_idx - 10)
                end_idx = min(total, base_idx + 10 + 1)
        else:
            if count is not None:
                start_idx = 0
                end_idx = min(total, count)
            else:
                start_idx = 0
                end_idx = total

        gdb.write(f"[+] Showing disassembly from {self.disasm_path}\n\n")

        for idx in range(start_idx, end_idx):
            text = lines[idx]
            instr_no = idx + 1  

            if pc_idx is not None and idx == pc_idx:
                gdb.write(f"{instr_no:6d}: --> {text}\n")
            else:
                gdb.write(f"{instr_no:6d}:     {text}\n")

class VmRegs(gdb.Command):
    
    def __init__(self):
        super().__init__("vm-regs", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        cfg = load_config()
        runtime_cfg = cfg.get("runtime", {})
        vm_mem_cfg = runtime_cfg.get("vm_mem", {})

        vm_base = _vm_state.get("vm_base")
        if vm_base is None:
            gdb.write("[-] vmdbg: vm_base is unknown; hit the dispatcher at least once.\n", gdb.STDERR)
            return

        regs_base_offset = vm_mem_cfg.get("regs_base_offset")
        if regs_base_offset is None:
            gdb.write("[-] vmdbg: vm_mem.regs_base_offset not configured.\n", gdb.STDERR)
            return

        reg_names = load_isa_register_order()
        if not reg_names:
            gdb.write("[-] vmdbg: no registers found in ISA.\n", gdb.STDERR)
            return

        inferior = gdb.selected_inferior()

        gdb.write(f"[+] VM base: 0x{vm_base:x}\n")
        gdb.write(f"[+] Regs base offset: {regs_base_offset}\n")

        for idx, reg in enumerate(reg_names):
            addr = vm_base + regs_base_offset + idx
            try:
                mem = inferior.read_memory(addr, 1)
                val = bytes(mem)[0]
                gdb.write(f"    {reg}: 0x{val:02x} (addr 0x{addr:x})\n")
            except gdb.MemoryError as e:
                gdb.write(f"    {reg}: <mem error: {e}>\n", gdb.STDERR)

class VmStackDump(gdb.Command):
    
    def __init__(self):
        super().__init__("vm-stack-dump", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        cfg = load_config()
        runtime_cfg = cfg.get("runtime", {})
        vm_mem_cfg = runtime_cfg.get("vm_mem", {})

        if not vm_mem_cfg.get("vm_stack", False):
            gdb.write("[-] vmdbg: vm_stack is not enabled in vmdbg_config.yml\n", gdb.STDERR)
            return

        vm_state_cfg = vm_mem_cfg.get("vm_state", {})
        stack_cfg = vm_mem_cfg.get("stack", {})

        symbol = vm_state_cfg.get("symbol")
        ptr_field = stack_cfg.get("ptr_field")
        depth_field = stack_cfg.get("depth_field")

        if not symbol or not ptr_field or not depth_field:
            gdb.write("[-] vmdbg: vm_state.symbol, stack.ptr_field, or stack.depth_field not configured\n", gdb.STDERR)
            return

        try:
            stack_ptr_val = gdb.parse_and_eval(f"{symbol}.{ptr_field}")
            stack_depth_val = gdb.parse_and_eval(f"{symbol}.{depth_field}")
        except gdb.error as e:
            gdb.write(f"[-] vmdbg: failed to read stack fields from {symbol}: {e}\n", gdb.STDERR)
            return

        try:
            stack_base = int(stack_ptr_val)
            stack_depth = int(stack_depth_val)
        except (TypeError, ValueError) as e:
            gdb.write(f"[-] vmdbg: invalid stack pointer/depth values: {e}\n", gdb.STDERR)
            return

        if stack_base == 0:
            gdb.write("[+] vmdbg: stack pointer is null\n")
            return

        sp_index = stack_depth - 1
        if sp_index < 0:
            gdb.write(f"[+] vmdbg: stack is empty (depth={stack_depth})\n")
            return

        count, unit, fmt = _parse_dump_flags(arg, default_count=20, default_unit="g", default_fmt="x")

        tos_addr = stack_base + sp_index * 8

        gdb.write(
            f"[+] vmdbg: dumping stack ({count}{unit}{fmt} from TOS, depth={stack_depth}, tos_idx={sp_index})\n"
        )

        _dump_vm_memory(tos_addr, count, unit, fmt)

class VmMemDump(gdb.Command):
    
    def __init__(self):
        super().__init__("vm-mem-dump", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        cfg = load_config()
        runtime_cfg = cfg.get("runtime", {})
        vm_mem_cfg = runtime_cfg.get("vm_mem", {})

        vm_state_cfg = vm_mem_cfg.get("vm_state", {})
        mem_cfg = vm_mem_cfg.get("memory", {})

        symbol = vm_state_cfg.get("symbol")
        ptr_field = mem_cfg.get("ptr_field")
        size_field = mem_cfg.get("size_field")

        if not symbol or not ptr_field:
            gdb.write("[-] vmdbg: vm_state.symbol or memory.ptr_field not configured\n", gdb.STDERR)
            return

        try:
            mem_ptr_val = gdb.parse_and_eval(f"{symbol}.{ptr_field}")
        except gdb.error as e:
            gdb.write(f"[-] vmdbg: failed to read memory pointer from {symbol}.{ptr_field}: {e}\n", gdb.STDERR)
            return

        try:
            mem_base = int(mem_ptr_val)
        except (TypeError, ValueError) as e:
            gdb.write(f"[-] vmdbg: invalid memory pointer value: {e}\n", gdb.STDERR)
            return

        if mem_base == 0:
            gdb.write("[+] vmdbg: memory pointer is null\n")
            return

        mem_size = None
        if size_field:
            try:
                mem_size_val = gdb.parse_and_eval(f"{symbol}.{size_field}")
                mem_size = int(mem_size_val)
            except (gdb.error, TypeError, ValueError):
                mem_size = None

        count, unit, fmt = _parse_dump_flags(arg, default_count=20, default_unit="g", default_fmt="x")

        gdb.write("[+] vmdbg: dumping VM memory")
        if mem_size is not None:
            gdb.write(f" ({count}{unit}{fmt} from base, size={mem_size})\n")
        else:
            gdb.write(f" ({count}{unit}{fmt} from base)\n")

        _dump_vm_memory(mem_base, count, unit, fmt)

class VmCallstackDump(gdb.Command):

    def __init__(self):
        super().__init__("vm-callstack-dump", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        cfg = load_config()
        runtime_cfg = cfg.get("runtime", {})
        vm_mem_cfg = runtime_cfg.get("vm_mem", {})

        vm_state_cfg = vm_mem_cfg.get("vm_state", {})
        cs_cfg = vm_mem_cfg.get("callstack", {})

        symbol = vm_state_cfg.get("symbol")
        ptr_field = cs_cfg.get("ptr_field")
        depth_field = cs_cfg.get("depth_field")

        if not symbol or not ptr_field or not depth_field:
            gdb.write(
                "[-] vmdbg: vm_state.symbol, callstack.ptr_field, or callstack.depth_field not configured\n",
                gdb.STDERR,
            )
            return

        try:
            cs_ptr_val = gdb.parse_and_eval(f"{symbol}.{ptr_field}")
            cs_depth_val = gdb.parse_and_eval(f"{symbol}.{depth_field}")
        except gdb.error as e:
            gdb.write(
                f"[-] vmdbg: failed to read callstack fields from {symbol}: {e}\n",
                gdb.STDERR,
            )
            return

        try:
            cs_base = int(cs_ptr_val)
            cs_depth = int(cs_depth_val)
        except (TypeError, ValueError) as e:
            gdb.write(f"[-] vmdbg: invalid callstack pointer/depth values: {e}\n", gdb.STDERR)
            return

        if cs_base == 0:
            gdb.write("[+] vmdbg: callstack pointer is null\n")
            return

        tos_index = cs_depth - 1
        if tos_index < 0:
            gdb.write(f"[+] vmdbg: callstack is empty (depth={cs_depth})\n")
            return

        count, unit, fmt = _parse_dump_flags(arg, default_count=20, default_unit="g", default_fmt="x")

        tos_addr = cs_base + tos_index * 8  

        gdb.write(
            f"[+] vmdbg: dumping VM callstack ({count}{unit}{fmt} from TOS, depth={cs_depth}, tos_idx={tos_index})\n"
        )

        _dump_vm_memory(tos_addr, count, unit, fmt)

class VmVmmap(gdb.Command):

    def __init__(self):
        super().__init__("vm-vmmap", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        cfg = load_config()
        runtime_cfg = cfg.get("runtime", {})
        vm_mem_cfg = runtime_cfg.get("vm_mem", {})

        if not vm_mem_cfg.get("vm_vmmap", False):
            gdb.write("[-] vmdbg: vm_vmmap is not enabled in vmdbg_config.yml\n", gdb.STDERR)
            return

        vm_state_cfg = vm_mem_cfg.get("vm_state", {})
        stack_cfg = vm_mem_cfg.get("stack", {})
        mem_cfg = vm_mem_cfg.get("memory", {})
        cs_cfg = vm_mem_cfg.get("callstack", {})
        pc_cfg = vm_mem_cfg.get("pc", {})
        bc_cfg = vm_mem_cfg.get("bytecode", {})

        entries = []

        vm_state_symbol = vm_state_cfg.get("symbol")
        vm_state_addr = None
        if vm_state_symbol:
            try:
                vm_state_addr = int(gdb.parse_and_eval(f"&{vm_state_symbol}"))
            except gdb.error:
                vm_state_addr = None

        if vm_state_cfg.get("in_vm_vmmap", False) and vm_state_addr is not None:
            entries.append({
                "name": "vm_state",
                "start": vm_state_addr,
                "end": None,
                "size": None,
                "value": None,
            })

        if pc_cfg.get("in_vm_vmmap", False) and vm_state_symbol:
            pc_field = pc_cfg.get("field")
            if pc_field:
                pc_addr = None
                pc_val = None
                try:
                    pc_addr_val = gdb.parse_and_eval(f"&{vm_state_symbol}.{pc_field}")
                    pc_addr = int(pc_addr_val)
                except gdb.error:
                    pc_addr = None

                try:
                    pc_val_expr = gdb.parse_and_eval(f"{vm_state_symbol}.{pc_field}")
                    pc_val = int(pc_val_expr)
                except (gdb.error, TypeError, ValueError):
                    pc_val = None

                if pc_addr is not None:
                    entries.append({
                        "name": "pc",
                        "start": pc_addr,
                        "end": None,
                        "size": None,
                        "value": pc_val,
                    })

        def add_region(name, section_cfg, elem_size):
            if not section_cfg.get("in_vm_vmmap", False):
                return
            if not vm_state_symbol:
                return

            ptr_field = section_cfg.get("ptr_field")
            size_field = section_cfg.get("size_field")
            if not ptr_field:
                return

            try:
                ptr_val = gdb.parse_and_eval(f"{vm_state_symbol}.{ptr_field}")
                base = int(ptr_val)
            except (gdb.error, TypeError, ValueError):
                base = None

            size = None
            if size_field:
                try:
                    size_val = gdb.parse_and_eval(f"{vm_state_symbol}.{size_field}")
                    size = int(size_val)
                except (gdb.error, TypeError, ValueError):
                    size = None

            if base is None or base == 0:
                return

            end = None
            if size is not None:
                end = base + size * elem_size

            entries.append({
                "name": name,
                "start": base,
                "end": end,
                "size": size,
                "value": None,
            })

        add_region("stack", stack_cfg, 8)
        add_region("memory", mem_cfg, 8)
        add_region("callstack", cs_cfg, 8)

        add_region("bytecode", bc_cfg, 1)

        if not entries:
            gdb.write("[+] vmdbg: no VM regions to display\n")
            return

        gdb.write("[+] vmdbg: VM memory map\n")
        gdb.write("{:<12} {:>18} {:>18} {:>10} {:>12}\n".format(
            "Name", "Start", "End", "Size", "Value"
        ))

        for e in entries:
            start = f"0x{e['start']:x}" if e.get("start") is not None else "-"
            end = f"0x{e['end']:x}" if e.get("end") is not None else "-"
            size = str(e["size"]) if e.get("size") is not None else "-"
            val = "" if e.get("value") is None else str(e["value"])
            gdb.write("{:<12} {:>18} {:>18} {:>10} {:>12}\n".format(
                e["name"], start, end, size, val
            ))

class VmBreak(gdb.Command):

    def __init__(self):
        super().__init__("vm-break", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        arg = arg.strip()
        if not arg:
            gdb.write("Usage: vm-break <pc_idx>\n", gdb.STDERR)
            return

        try:
            pc_idx = int(arg, 0)  
        except ValueError:
            gdb.write(f"[-] vmdbg: invalid pc_idx {arg!r}; expected integer\n", gdb.STDERR)
            return

        bps = _vm_state.get("vm_breakpoints")
        if bps is None:
            bps = set()
            _vm_state["vm_breakpoints"] = bps

        first = len(bps) == 0
        bps.add(pc_idx)

        gdb.write(f"[+] vmdbg: set VM breakpoint at pc={pc_idx}\n")
        if first:
            gdb.write("[+] vmdbg: dispatcher will now only stop at VM breakpoints.\n")

class VmNext(gdb.Command):
  

    def __init__(self):
        super().__init__("vm-next", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        _vm_state["single_step"] = True
        gdb.execute("continue", from_tty=from_tty)

class VmNi(gdb.Command):
   
    def __init__(self):
        super().__init__("vm-ni", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        gdb.execute("vm-next", from_tty=from_tty)


_vm_dispatch_bp = VmDispatcherBreakpoint()

ShowDisasm()
VmRegs()
VmStackDump()
VmMemDump()
VmCallstackDump()
VmVmmap()
VmBreak()
VmNext()
VmNi()