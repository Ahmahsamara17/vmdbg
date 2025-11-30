# vmdbg.py
import gdb
import yaml
import os

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
    """
    Returns a list of VM register names in a stable order, based on vm_isa.yml.
    Uses isa_file from vmdbg_config.yml or defaults to ./vm_isa.yml.
    """
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
    """
    Read one-byte VM register by name from VM memory.
    Layout: regs_base_offset + index(reg_name) in ISA register order.
    Returns int [0..255] or None on failure.
    """
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
        """
        Return the base address of the main executable using:
          - 'info files' to get the path
          - 'info proc mappings' to find the mapping
        Works on standard Linux GDB/GEF, no Progspace.executable_filename needed.
        """
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

        pc_reg_name = vm_mem_cfg.get("pc_reg")  
        if pc_reg_name and _vm_state.get("vm_base") is not None:
            pc_val = read_vm_reg_byte(_vm_state["vm_base"], pc_reg_name)
            if pc_val is not None:
                _vm_state["pc_index"] = pc_val
            else:
                _vm_state["pc_index"] = None

        gdb.write(f"[vmdbg] dispatcher hit #{_vm_state['step']}")
        if _vm_state.get("pc_index") is not None:
            gdb.write(f" (pc={_vm_state['pc_index']})")
        gdb.write("\n")

        return True


_vm_dispatch_bp = VmDispatcherBreakpoint()


class ShowDisasm(gdb.Command):
    """
    vm-disasm
    Print the precomputed yan85 disassembly stored in disasm.file
    defined in vmdbg_config.yml, with an arrow at the current PC.
    """

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
            current_idx = pc_idx - 1
        elif _vm_state.get("step", 0) > 0:
            current_idx = _vm_state["step"] - 1
        else:
            current_idx = None

        for idx, text in enumerate(lines):
            if current_idx is not None and idx == current_idx:
                gdb.write("                  --> " + text + "\n")
            else:
                gdb.write("\t\t\t" + text + "\n")


ShowDisasm()


class VmRegs(gdb.Command):
    """
    vm-regs
    Read the VM register block from VM memory and print a,b,c,d,s,i,f.
    """

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

