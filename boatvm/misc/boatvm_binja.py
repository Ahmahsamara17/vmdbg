from binaryninja import *
from binaryninja.architecture import Architecture
from binaryninja.function import RegisterInfo, InstructionInfo, InstructionTextToken
from binaryninja.enums import InstructionTextTokenType, BranchType
from binaryninja.lowlevelil import LowLevelILLabel
import struct


class BoatVMArchitecture(Architecture):
    name = "BoatVM"

    address_size = 8
    default_int_size = 8
    instr_alignment = 16
    max_instr_length = 16

    regs = {
        "sp": RegisterInfo("sp", 8),
        "pc": RegisterInfo("pc", 8),
        "flags": RegisterInfo("flags", 1),
    }

    stack_pointer = "sp"

    flags = ["div0", "prec", "inv", "of", "uf"]
    flag_roles = {
        "div0": FlagRole.ZeroFlagRole,
        "prec": FlagRole.SpecialFlagRole,
        "inv": FlagRole.SpecialFlagRole,
        "of": FlagRole.OverflowFlagRole,
        "uf": FlagRole.SpecialFlagRole,
    }

    flag_write_types = ["*"]
    flags_written_by_flag_write_type = {"*": ["div0", "prec", "inv", "of", "uf"]}

    intrinsics = {
        "floor": IntrinsicInfo([Type.float(8)], [Type.float(8)]),
        "ceil": IntrinsicInfo([Type.float(8)], [Type.float(8)]),
        "trunc": IntrinsicInfo([Type.float(8)], [Type.float(8)]),
        "round": IntrinsicInfo([Type.float(8)], [Type.float(8)]),
        "abs": IntrinsicInfo([Type.float(8)], [Type.float(8)]),
        "min": IntrinsicInfo([Type.float(8)], [Type.float(8), Type.float(8)]),
        "max": IntrinsicInfo([Type.float(8)], [Type.float(8), Type.float(8)]),
        "print_double": IntrinsicInfo([], [Type.float(8)]),
        "putc": IntrinsicInfo([Type.int(8)], []),
        "read_double": IntrinsicInfo([Type.float(8)], []),
        "getc": IntrinsicInfo([], [Type.float(8)]),
    }

    OPCODES = {
        0x00: "push",
        0x01: "pop",
        0x02: "dup",
        0x03: "dup2",
        0x04: "rot3",
        0x05: "swap",
        0x06: "nop",
        0x07: "add",
        0x08: "sub",
        0x09: "mul",
        0x0A: "div",
        0x0B: "floor",
        0x0C: "ceiling",
        0x0D: "trunc",
        0x0E: "round",
        0x0F: "abs",
        0x10: "min",
        0x11: "max",
        0x12: "clear_flags",
        0x13: "jmp_div0",
        0x14: "jmp_prec",
        0x15: "jmp_inv",
        0x16: "jmp_of",
        0x17: "jmp_uf",
        0x18: "jmp_anyf",
        0x19: "jmp",
        0x1A: "call",
        0x1B: "ret",
        0x1C: "print_double",
        0x1D: "putc",
        0x1E: "read_double",
        0x1F: "getc",
        0x20: "load",
        0x21: "store",
    }

    def get_instruction_info(self, data, addr):
        info = InstructionInfo()
        if len(data) < 16:
            return info

        try:
            opcode, operand = struct.unpack("<Qd", data[:16])
        except:
            return info

        if opcode not in self.OPCODES:
            return info

        info.length = 16

        if opcode == 0x1B:  # ret
            info.add_branch(BranchType.FunctionReturn)
        elif opcode == 0x1A:  # call
            info.add_branch(BranchType.CallDestination, int(operand) * 16)
        elif opcode in [0x13, 0x14, 0x15, 0x16, 0x17, 0x18]:  # conditional branches
            target = addr + 16 + int(operand) * 16
            info.add_branch(BranchType.TrueBranch, target)
            info.add_branch(BranchType.FalseBranch, addr + 16)
        elif opcode == 0x19:  # unconditional branch
            target = addr + 16 + int(operand) * 16
            info.add_branch(BranchType.UnconditionalBranch, target)

        return info

    def get_instruction_text(self, data, addr):
        if len(data) < 16:
            return [], 0

        try:
            opcode, operand = struct.unpack("<Qd", data[:16])
        except:
            return [], 0

        if opcode not in self.OPCODES:
            tokens = [
                InstructionTextToken(
                    InstructionTextTokenType.InstructionToken,
                    f"unknown_op_{int(opcode):x}",
                )
            ]
            tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, " "))
            tokens.append(
                InstructionTextToken(
                    InstructionTextTokenType.IntegerToken, str(operand)
                )
            )
            return tokens, 16

        mnemonic = self.OPCODES[opcode]
        tokens = [
            InstructionTextToken(InstructionTextTokenType.InstructionToken, mnemonic)
        ]

        if opcode == 0x00:  # push
            tokens.extend(
                [
                    InstructionTextToken(
                        InstructionTextTokenType.OperandSeparatorToken, " "
                    ),
                    InstructionTextToken(
                        InstructionTextTokenType.IntegerToken, f"{operand}"
                    ),
                ]
            )
            if int(operand) == operand and 31 < operand < 128:
                tokens.extend(
                    [
                        InstructionTextToken(
                            InstructionTextTokenType.OperandSeparatorToken, "     ; "
                        ),
                        InstructionTextToken(
                            InstructionTextTokenType.TextToken, chr(int(operand))
                        ),
                    ]
                )
        elif opcode == 0x1A:  # call
            tokens.extend(
                [
                    InstructionTextToken(
                        InstructionTextTokenType.OperandSeparatorToken, " "
                    ),
                    InstructionTextToken(
                        InstructionTextTokenType.PossibleAddressToken,
                        str(int(operand)),
                        int(operand) * 16,
                    ),
                ]
            )
        elif opcode in [0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19]:  # jumps
            tokens.extend(
                [
                    InstructionTextToken(
                        InstructionTextTokenType.OperandSeparatorToken, " "
                    ),
                    InstructionTextToken(
                        InstructionTextTokenType.PossibleAddressToken,
                        f"pc+{int(operand)}",
                        addr + 16 + int(operand) * 16,
                    ),
                ]
            )

        return tokens, 16

    def get_instruction_low_level_il(self, data, addr, il):
        if len(data) < 16:
            return il.unimplemented()

        try:
            opcode, operand = struct.unpack("<Qd", data[:16])
            opcode = int(opcode)
        except:
            return il.unimplemented()

        if opcode not in self.OPCODES:
            il.append(il.undefined())
            return 16

        if opcode == 0x00:  # push
            il.append(il.push(8, il.const(8, int(operand))))
        elif opcode == 0x01:  # pop
            il.append(il.pop(8))
        elif opcode == 0x02:  # dup
            val = il.pop(8)
            il.append(il.push(8, val))
            il.append(il.push(8, val))
        elif opcode == 0x03:  # dup2
            val1 = il.pop(8)
            val2 = il.pop(8)
            il.append(il.push(8, val2))
            il.append(il.push(8, val1))
            il.append(il.push(8, val2))
            il.append(il.push(8, val1))
        elif opcode == 0x04:  # rot3
            val1 = il.pop(8)
            val2 = il.pop(8)
            val3 = il.pop(8)
            il.append(il.push(8, val2))
            il.append(il.push(8, val1))
            il.append(il.push(8, val3))
        elif opcode == 0x05:  # swap
            val1 = il.pop(8)
            val2 = il.pop(8)
            il.append(il.push(8, val1))
            il.append(il.push(8, val2))
        elif opcode == 0x06:  # nop
            il.append(il.nop())
        elif opcode == 0x07:  # add
            val2 = il.pop(8)
            val1 = il.pop(8)
            il.append(il.push(8, il.add(8, val1, val2)))
        elif opcode == 0x08:  # sub
            val2 = il.pop(8)
            val1 = il.pop(8)
            il.append(il.push(8, il.sub(8, val1, val2)))
        elif opcode == 0x09:  # mul
            val2 = il.pop(8)
            val1 = il.pop(8)
            il.append(il.push(8, il.mult(8, val1, val2)))
        elif opcode == 0x0A:  # div
            val2 = il.pop(8)
            val1 = il.pop(8)
            il.append(il.push(8, il.div_signed(8, val1, val2)))
        elif opcode == 0x0B:  # floor
            val = il.pop(8)
            result = il.intrinsic([], "floor", [val])
            il.append(il.push(8, result))
        elif opcode == 0x0C:  # ceiling
            val = il.pop(8)
            result = il.intrinsic([], "ceil", [val])
            il.append(il.push(8, result))
        elif opcode == 0x0D:  # trunc
            val = il.pop(8)
            result = il.intrinsic([], "trunc", [val])
            il.append(il.push(8, result))
        elif opcode == 0x0E:  # round
            val = il.pop(8)
            result = il.intrinsic([], "round", [val])
            il.append(il.push(8, result))
        elif opcode == 0x0F:  # abs
            val = il.pop(8)
            result = il.intrinsic([], "abs", [val])
            il.append(il.push(8, result))
        elif opcode == 0x10:  # min
            val2 = il.pop(8)
            val1 = il.pop(8)
            result = il.intrinsic([], "min", [val1, val2])
            il.append(il.push(8, result))
        elif opcode == 0x11:  # max
            val2 = il.pop(8)
            val1 = il.pop(8)
            result = il.intrinsic([], "max", [val1, val2])
            il.append(il.push(8, result))
        elif opcode == 0x12:  # clear_flags
            il.append(il.set_flag("div0", il.const(1, 0)))
            il.append(il.set_flag("prec", il.const(1, 0)))
            il.append(il.set_flag("inv", il.const(1, 0)))
            il.append(il.set_flag("of", il.const(1, 0)))
            il.append(il.set_flag("uf", il.const(1, 0)))
        elif opcode in [0x13, 0x14, 0x15, 0x16, 0x17, 0x18]:  # conditional branches
            flag_name = ["div0", "prec", "inv", "of", "uf", "anyf"][opcode - 0x13]
            if flag_name == "anyf":
                condition = il.or_expr(
                    1,
                    il.or_expr(
                        1,
                        il.or_expr(
                            1,
                            il.or_expr(1, il.flag("div0"), il.flag("prec")),
                            il.flag("inv"),
                        ),
                        il.flag("of"),
                    ),
                    il.flag("uf"),
                )
            else:
                condition = il.flag(flag_name)

            true_target = addr + 16 + int(operand) * 16
            false_target = addr + 16

            t = LowLevelILLabel()
            f = LowLevelILLabel()

            il.append(il.if_expr(condition, t, f))
            il.mark_label(t)
            il.append(il.jump(il.const(8, true_target)))
            il.mark_label(f)
            il.append(il.jump(il.const(8, false_target)))
        elif opcode == 0x19:  # jmp
            il.append(il.jump(il.const(8, addr + 16 + int(operand) * 16)))
        elif opcode == 0x1A:  # call
            il.append(il.call(il.const(8, int(operand) * 16)))
        elif opcode == 0x1B:  # ret
            il.append(il.ret(il.pop(8)))
        elif opcode == 0x1C:  # print_double
            val = il.pop(8)
            il.append(il.intrinsic([], "print_double", [val]))
        elif opcode == 0x1D:  # putc
            val = il.pop(8)
            il.append(il.intrinsic([], "putc", [val]))
        elif opcode == 0x1E:  # read_double
            result = il.intrinsic([], "read_double", [])
            il.append(il.push(8, result))
        elif opcode == 0x1F:  # getc
            result = il.intrinsic([], "getc", [])
            il.append(il.push(8, result))
        elif opcode == 0x20:  # load
            addr_val = il.pop(8)
            il.append(il.push(8, il.load(8, addr_val)))
        elif opcode == 0x21:  # store
            addr_val = il.pop(8)
            val = il.pop(8)
            il.append(il.store(8, addr_val, val))
        else:
            il.append(il.undefined())

        return 16


class BoatVMView(BinaryView):
    name = "BoatVM"
    long_name = "BoatVM Bytecode"

    @classmethod
    def is_valid_for_data(cls, data):
        if data.length % 16 != 0 or data.length == 0:
            return False

        if data.length >= 16:
            try:
                opcode, operand = struct.unpack("<Qd", data[:16])
                return 0 <= opcode <= 0x21
            except:
                return False
        return False

    def __init__(self, data):
        BinaryView.__init__(self, parent_view=data, file_metadata=data.file)
        self.platform = Architecture["BoatVM"].standalone_platform
        self.arch = Architecture["BoatVM"]

    def perform_get_address_size(self):
        return 8

    def init(self):
        try:
            data = self.parent_view.read(0, self.parent_view.length)
            instr_count = len(data) // 16

            self.add_auto_segment(
                0,
                instr_count * 16,
                0,
                instr_count * 16,
                SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable,
            )

            self.add_auto_section(
                "CODE",
                0,
                instr_count * 16,
                SectionSemantics.ReadOnlyCodeSectionSemantics,
            )

            self.add_entry_point(0)
            self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, 0, "start"))

            return True
        except Exception as e:
            log_error(f"BoatVM init failed: {e}")
            return False


BoatVMArchitecture.register()
BoatVMView.register()
