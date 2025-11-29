# vmdbg.py
import gdb
import yaml
import os

# -------- VM STATE: dispatcher hit counter --------
_vm_state = {
    "step": 0,  
}


class VmDispatcherBreakpoint(gdb.Breakpoint):

    def __init__(self, config_path="vmdbg_config.yml"):
        self.config_path = config_path

        dispatcher_spec = self._get_dispatcher_spec()
        if dispatcher_spec is None:
            gdb.write("[-] vmdbg: dispatcher not configured; hit counting disabled.\n")
            self.valid = False
            return

        try:
            super().__init__(dispatcher_spec, gdb.BP_BREAKPOINT, internal=False)
            self.silent = True
            self.valid = True
            gdb.write(f"[+] vmdbg: dispatcher breakpoint set on {dispatcher_spec}\n")
        except gdb.error as e:
            gdb.write(f"[-] vmdbg: failed to set dispatcher breakpoint: {e}\n", gdb.STDERR)
            self.valid = False

    def _get_exe_base(self):
        ps = gdb.current_progspace()
        exe = getattr(ps, "executable_filename", None)
        if not exe:
            gdb.write("[-] vmdbg: no executable filename in current progspace\n", gdb.STDERR)
            return None

        try:
            out = gdb.execute("info proc mappings", to_string=True)
        except gdb.error as e:
            gdb.write(f"[-] vmdbg: 'info proc mappings' failed: {e}\n", gdb.STDERR)
            return None

        base = None
        for line in out.splitlines():
            if exe in line:
                parts = line.split()
                if len(parts) >= 5:
                    try:
                        base = int(parts[0], 16)
                        break
                    except ValueError:
                        continue

        if base is None:
            gdb.write(f"[-] vmdbg: could not find mapping for {exe} in info proc mappings\n", gdb.STDERR)

        return base

    def _get_dispatcher_spec(self):
        if not os.path.exists(self.config_path):
            gdb.write(f"[-] vmdbg: config file not found: {self.config_path}\n", gdb.STDERR)
            return None

        with open(self.config_path, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}

        runtime_cfg = cfg.get("runtime", {})

        sym = runtime_cfg.get("dispatcher_symbol")
        if sym:
            return sym

        disp_off = runtime_cfg.get("dispatcher_offset")
        if disp_off is None:
            return None

        try:
            disp_off_int = int(str(disp_off), 0)
        except ValueError:
            gdb.write(f"[-] vmdbg: invalid dispatcher_offset {disp_off!r}\n", gdb.STDERR)
            return None

        base = self._get_exe_base()
        if base is None:
            return None

        addr = base + disp_off_int
        return f"*0x{addr:x}"

    def stop(self):
        _vm_state["step"] += 1
        gdb.write(f"[vmdbg] dispatcher hit #{_vm_state['step']}\n")
        return True


_vm_dispatch_bp = VmDispatcherBreakpoint()


class ShowDisasm(gdb.Command):

    def __init__(self):
        super().__init__("vm-disasm", gdb.COMMAND_USER)
        self.config_path = "vmdbg_config.yml"
        self.disasm_path = None
        self._load_config()

    def _load_config(self):
        if not os.path.exists(self.config_path):
            gdb.write(f"[-] vmdbg config file not found: {self.config_path}\n", gdb.STDERR)
            self.disasm_path = None
            return

        with open(self.config_path, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}

        disasm_cfg = cfg.get("disasm", {})
        disasm_path = disasm_cfg.get("file")

        if not disasm_path:
            gdb.write("[-] disasm.file missing in vmdbg_config.yml\n", gdb.STDERR)
            self.disasm_path = None
            return

        self.disasm_path = disasm_path

    def invoke(self, arg, from_tty):
        if self.disasm_path is None:
            self._load_config()
            if self.disasm_path is None:
                return

        if not os.path.exists(self.disasm_path):
            gdb.write(f"[-] Disasm file not found: {self.disasm_path}\n", gdb.STDERR)
            return

        try:
            with open(self.disasm_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
        except OSError as e:
            gdb.write(f"[-] Failed to read disasm file: {e}\n", gdb.STDERR)
            return

        gdb.write(f"[+] Showing disassembly from {self.disasm_path}\n\n")

        if _vm_state["step"] > 0:
            current_idx = _vm_state["step"] - 1
        else:
            current_idx = None

        for idx, line in enumerate(lines):
            text = line.rstrip("\n")

            if current_idx is not None and idx == current_idx:
                gdb.write("                  --> " + text + "\n")
            else:
                gdb.write("\t\t\t" + text + "\n")


ShowDisasm()

