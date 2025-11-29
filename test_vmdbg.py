# vmdbg.py

import gdb
import yaml
import os

_vm_config = None
_vm_state = {
    "step": 0,
    "vm_base": None,
}


def load_config(path="vmdbg_config.yml"):
    global _vm_config
    if _vm_config is not None:
        return _vm_config

    if not os.path.exists(path):
        gdb.write(f"[-] vmdbg: config file not found: {path}\n", gdb.STDERR)
        _vm_config = {}
        return _vm_config

    with open(path, "r") as f:
        _vm_config = yaml.safe_load(f) or {}
    return _vm_config


def load_isa_register_order():
    """
    Read vm_isa.yml (via isa_file in vmdbg_config.yml) and return
    a list of register names in a stable order.

    We only care about names here; memory layout is
    regs_base_offset + index in this list.
    """
    cfg = load_config()
    isa_path = cfg.get("isa_file", "vm_isa.yml")

    if not os.path.exists(isa_path):
        gdb.write(f"[-] vmdbg: ISA file not found: {isa_path}\n", gdb.STDERR)
        return []

    with open(isa_path, "r") as f:
        isa = yaml.safe_load(f) or {}

    reg_map = isa.get("registers", {})

    # reg_map looks like {"0x20": "a", "0x04": "b", ...}
    # We just want the names. The YAML order may or may not be nice, so:
    names_in_file = list(reg_map.values())

    # Prefer a sensible canonical order if present:
    preferred = ["a", "b", "c", "d", "s", "i", "f"]
    ordered = [r for r in preferred if r in names_in_file]

    # If ISA ever adds extra regs not in preferred, append them deterministically.
    extras = sorted(r for r in names_in_file if r not in ordered)
    return ordered + extras


class VmDispatcherBreakpoint(gdb.Breakpoint):
    def __init__(self, config_path="vmdbg_config.yml"):
        self.config_path = config_path
        cfg = load_config(config_path)
        runtime_cfg = cfg.get("runtime", {})

        spec = None
        sym = runtime_cfg.get("dispatcher_symbol")
        if sym:
            spec = sym
        else:
            disp_off = runtime_cfg.get("dispatcher_offset")
            if disp_off is not None:
                try:
                    off = int(str(disp_off), 0)
                    spec = f"*0x{off:x}"
                except ValueError:
                    gdb.write(f"[-] vmdbg: invalid dispatcher_offset {disp_off!r}\n", gdb.STDERR)

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

        gdb.write(f"[vmdbg] dispatcher hit #{_vm_state['step']}\n")
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

        with open(self.disasm_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        gdb.write(f"[+] Showing disassembly from {self.disasm_path}\n\n")

        current_idx = _vm_state["step"] - 1 if _vm_state["step"] > 0 else None

        for idx, line in enumerate(lines):
            text = line.rstrip("\n")
            if current_idx is not None and idx == current_idx:
                gdb.write("                  --> " + text + "\n")
            else:
                gdb.write("\t\t\t" + text + "\n")


ShowDisasm()


class VmRegs(gdb.Command):
    """
    vm-regs
    Read VM registers from memory based on vm_isa.yml and vmdbg_config.yml.
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
            gdb.write("[-] vmdbg: no registers found in ISA file.\n", gdb.STDERR)
            return

        inferior = gdb.selected_inferior()

        gdb.write(f"[+] VM base: 0x{vm_base:x}\n")
        gdb.write(f"[+] Regs base offset: {regs_base_offset}\n")

        for idx, reg in enumerate(reg_names):
            addr = vm_base + regs_base_offset + idx
            try:
                mem = inferior.read_memory(addr, 1)
                # Robust: convert whatever GDB gives us into a bytes, then take first byte
                val = bytes(mem)[0]

                gdb.write(f"    {reg}: 0x{val:02x} (addr 0x{addr:x})\n")
            except gdb.MemoryError as e:
                gdb.write(f"    {reg}: <mem error: {e}>\n", gdb.STDERR)




VmRegs()

