# vmdbg.py
import gdb
import yaml
import os
import struct

_vm_config = None
_vm_state = {
    "step": 0,        
    "vm_base": None,  
    "pc_index": None, 
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

        gdb.write(f"[vmdbg] dispatcher hit #{_vm_state['step']}")
        if pc_index is not None:
            gdb.write(f" (pc={pc_index})")
        gdb.write("\n")

        return True



_vm_dispatch_bp = VmDispatcherBreakpoint()


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
            gdb.write("[-] vmdbg: disasm.file missing in vmdbg_config.yml\n", gdb.STDERR)
            return
        self.disasm_path = path

    def invoke(self, arg, from_tty):
        if self.disasm_path is None:
            self._load_disasm_path()
            if self.disasm_path is None:
                return

        if not os.path.exists(self.disasm_path):
            gdb.write(f"[-] Disasm file not found: {self.disasm_path}\n", gdb.STDERR)
            return

        try:
            with open(self.disasm_path, "r", encoding="utf-8") as f:
                raw_lines = f.readlines()
        except OSError as e:
            gdb.write(f"[-] Failed to read disasm file: {e}\n", gdb.STDERR)
            return

        lines = [line.rstrip("\n") for line in raw_lines]

        gdb.write(f"[+] Showing disassembly from {self.disasm_path}\n\n")

        pc_idx = _vm_state.get("pc_index")
        if pc_idx is not None and 0 <= pc_idx < len(lines):
            current_idx = pc_idx
        elif _vm_state.get("step", 0) > 0:
            current_idx = _vm_state["step"] - 1
        else:
            current_idx = None

        if current_idx is not None:
            start_idx = max(0, current_idx - 10)
            end_idx = min(len(lines), current_idx + 10 + 1)
            idx_range = range(start_idx, end_idx)
        else:
            idx_range = range(len(lines))

        for idx in idx_range:
            text = lines[idx]
            instr_no = idx + 1  

            if current_idx is not None and idx == current_idx:
                gdb.write(f"{instr_no:6d}: --> {text}\n")
            else:
                gdb.write(f"{instr_no:6d}:     {text}\n")

ShowDisasm()


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


VmRegs()


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

        max_to_dump = 20
        inferior = gdb.selected_inferior()
        elem_size = 8  

        start_addr = stack_base + sp_index * elem_size

        gdb.write(f"[+] vmdbg: dumping stack (20 qwords from TOS, depth={stack_depth}, tos_idx={sp_index})\n")

        for i in range(0, max_to_dump, 2):
            line_addr = start_addr + i * elem_size
            gdb.write(f"0x{line_addr:016x}: ")

            vals = []
            for j in range(2):
                if i + j >= max_to_dump:
                    break
                addr = line_addr + j * elem_size
                try:
                    mem = inferior.read_memory(addr, elem_size)
                    raw = bytes(mem)
                    (qword,) = struct.unpack("<Q", raw)
                    vals.append(f"0x{qword:016x}")
                except gdb.MemoryError:
                    vals.append("<memerr>")

            gdb.write("  ".join(vals) + "\n")


VmStackDump()


class VmMemDump(gdb.Command):
    
    def __init__(self):
        super().__init__("vm-mem-dump", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        cfg = load_config()
        runtime_cfg = cfg.get("runtime", {})
        vm_mem_cfg = runtime_cfg.get("vm_mem", {})

        # We don't require vm_stack here; just that memory is described
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

        max_to_dump = 20
        elem_size = 8 
        inferior = gdb.selected_inferior()

        gdb.write("[+] vmdbg: dumping VM memory")
        if mem_size is not None:
            gdb.write(f" (20 qwords from base, size={mem_size})\n")
        else:
            gdb.write(" (20 qwords from base)\n")

        start_addr = mem_base

        for i in range(0, max_to_dump, 2):
            line_addr = start_addr + i * elem_size
            gdb.write(f"0x{line_addr:016x}: ")

            vals = []
            for j in range(2):
                if i + j >= max_to_dump:
                    break
                addr = line_addr + j * elem_size
                try:
                    mem = inferior.read_memory(addr, elem_size)
                    raw = bytes(mem)
                    (qword,) = struct.unpack("<Q", raw)
                    vals.append(f"0x{qword:016x}")
                except gdb.MemoryError:
                    vals.append("<memerr>")

            gdb.write("  ".join(vals) + "\n")

VmMemDump()

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

        max_to_dump = 20
        elem_size = 8  
        inferior = gdb.selected_inferior()

        start_addr = cs_base + tos_index * elem_size

        gdb.write(
            f"[+] vmdbg: dumping VM callstack (20 qwords from TOS, depth={cs_depth}, tos_idx={tos_index})\n"
        )

        for i in range(0, max_to_dump, 2):
            line_addr = start_addr + i * elem_size
            gdb.write(f"0x{line_addr:016x}: ")

            vals = []
            for j in range(2):
                if i + j >= max_to_dump:
                    break
                addr = line_addr + j * elem_size
                try:
                    mem = inferior.read_memory(addr, elem_size)
                    raw = bytes(mem)
                    (qword,) = struct.unpack("<Q", raw)
                    vals.append(f"0x{qword:016x}")
                except gdb.MemoryError:
                    vals.append("<memerr>")

            gdb.write("  ".join(vals) + "\n")

VmCallstackDump()