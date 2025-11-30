import struct
from binaryninja import *


class BoatVMArchitecture(Architecture):
    name = "boatvm"
    address_size = 8
    default_int_size = 8
    instr_alignment = 16
    max_instr_length = 16
    
    regs = {"stack": RegisterInfo("stack", 8)}
    stack_pointer = "stack"

    def get_instruction_info(self, data, addr):
        if len(data) < 16:
            return None
            
        try:
            opcode, operand = struct.unpack("<Qd", data[:16])
            
            info = InstructionInfo()
            info.length = 16
            
            # Handle jumps and calls
            if opcode in [0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19]:  # jmp variants
                target = addr + 16 + int(operand) * 16
                info.add_branch(BranchType.TrueBranch, target)
                if opcode != 0x19:  # conditional jumps also continue
                    info.add_branch(BranchType.FalseBranch, addr + 16)
            elif opcode == 0x1A:  # call
                target = int(operand) * 16
                info.add_branch(BranchType.CallDestination, target)
            elif opcode == 0x1B:  # ret
                info.add_branch(BranchType.FunctionReturn)
                
            return info
        except:
            return None

    def get_instruction_text(self, data, addr):
        if len(data) < 16:
            return None
            
        try:
            opcode, operand = struct.unpack("<Qd", data[:16])
            
            tokens = []
            
            if opcode == 0x0:
                tokens.append(InstructionTextToken(InstructionTextTokenType.InstructionToken, "push"))
                tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, " "))
                tokens.append(InstructionTextToken(InstructionTextTokenType.FloatingPointToken, str(operand)))
                if int(operand) == operand and 31 < operand < 128:
                    tokens.append(InstructionTextToken(InstructionTextTokenType.CommentToken, f"     ; {chr(int(operand))}"))
            elif opcode == 0x1:
                tokens.append(InstructionTextToken(InstructionTextTokenType.InstructionToken, "pop"))
            elif opcode == 0x2:
                tokens.append(InstructionTextToken(InstructionTextTokenType.InstructionToken, "dup"))
            elif opcode == 0x3:
                tokens.append(InstructionTextToken(InstructionTextTokenType.InstructionToken, "dup2"))
            elif opcode == 0x4:
                tokens.append(InstructionTextToken(InstructionTextTokenType.InstructionToken, "rot3"))
            elif opcode == 0x5:
                tokens.append(InstructionTextToken(InstructionTextTokenType.InstructionToken, "swap"))
            elif opcode == 0x6:
                tokens.append(InstructionTextToken(InstructionTextTokenType.InstructionToken, "nop"))
            elif opcode == 0x7:
                tokens.append(InstructionTextToken(InstructionTextTokenType.InstructionToken, "add"))
            elif opcode == 0x8:
                tokens.append(InstructionTextToken(InstructionTextTokenType.InstructionToken, "sub"))
            elif opcode == 0x9:
                tokens.append(InstructionTextToken(InstructionTextTokenType.InstructionToken, "mul"))
            elif opcode == 0xA:
                tokens.append(InstructionTextToken(InstructionTextTokenType.InstructionToken, "div"))
            elif opcode == 0x10:
                tokens.append(InstructionTextToken(InstructionTextTokenType.InstructionToken, "min"))
            elif opcode == 0x11:
                tokens.append(InstructionTextToken(InstructionTextTokenType.InstructionToken, "max"))
            elif opcode == 0xB:
                tokens.append(InstructionTextToken(InstructionTextTokenType.InstructionToken, "floor"))
            elif opcode == 0xC:
                tokens.append(InstructionTextToken(InstructionTextTokenType.InstructionToken, "ceiling"))
            elif opcode == 0xD:
                tokens.append(InstructionTextToken(InstructionTextTokenType.InstructionToken, "trunc"))
            elif opcode == 0xE:
                tokens.append(InstructionTextToken(InstructionTextTokenType.InstructionToken, "round"))
            elif opcode == 0xF:
                tokens.append(InstructionTextToken(InstructionTextTokenType.InstructionToken, "abs"))
            elif opcode == 0x12:
                tokens.append(InstructionTextToken(InstructionTextTokenType.InstructionToken, "clear_flags"))
            elif opcode == 0x13:
                tokens.append(InstructionTextToken(InstructionTextTokenType.InstructionToken, "jmp_div0"))
                tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, " "))
                target = addr + 16 + int(operand) * 16
                tokens.append(InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, hex(target), target))
            elif opcode == 0x14:
                tokens.append(InstructionTextToken(InstructionTextTokenType.InstructionToken, "jmp_prec"))
                tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, " "))
                target = addr + 16 + int(operand) * 16
                tokens.append(InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, hex(target), target))
            elif opcode == 0x15:
                tokens.append(InstructionTextToken(InstructionTextTokenType.InstructionToken, "jmp_inv"))
                tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, " "))
                target = addr + 16 + int(operand) * 16
                tokens.append(InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, hex(target), target))
            elif opcode == 0x16:
                tokens.append(InstructionTextToken(InstructionTextTokenType.InstructionToken, "jmp_of"))
                tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, " "))
                target = addr + 16 + int(operand) * 16
                tokens.append(InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, hex(target), target))
            elif opcode == 0x17:
                tokens.append(InstructionTextToken(InstructionTextTokenType.InstructionToken, "jmp_uf"))
                tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, " "))
                target = addr + 16 + int(operand) * 16
                tokens.append(InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, hex(target), target))
            elif opcode == 0x18:
                tokens.append(InstructionTextToken(InstructionTextTokenType.InstructionToken, "jmp_anyf"))
                tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, " "))
                target = addr + 16 + int(operand) * 16
                tokens.append(InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, hex(target), target))
            elif opcode == 0x19:
                tokens.append(InstructionTextToken(InstructionTextTokenType.InstructionToken, "jmp"))
                tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, " "))
                target = addr + 16 + int(operand) * 16
                tokens.append(InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, hex(target), target))
            elif opcode == 0x1A:
                tokens.append(InstructionTextToken(InstructionTextTokenType.InstructionToken, "call"))
                tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, " "))
                target = int(operand) * 16
                tokens.append(InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, hex(target), target))
            elif opcode == 0x1B:
                tokens.append(InstructionTextToken(InstructionTextTokenType.InstructionToken, "ret"))
            elif opcode == 0x1C:
                tokens.append(InstructionTextToken(InstructionTextTokenType.InstructionToken, "print_double"))
            elif opcode == 0x1D:
                tokens.append(InstructionTextToken(InstructionTextTokenType.InstructionToken, "putc"))
            elif opcode == 0x1E:
                tokens.append(InstructionTextToken(InstructionTextTokenType.InstructionToken, "read_double"))
            elif opcode == 0x1F:
                tokens.append(InstructionTextToken(InstructionTextTokenType.InstructionToken, "getc"))
            elif opcode == 0x20:
                tokens.append(InstructionTextToken(InstructionTextTokenType.InstructionToken, "load"))
            elif opcode == 0x21:
                tokens.append(InstructionTextToken(InstructionTextTokenType.InstructionToken, "store"))
            else:
                tokens.append(InstructionTextToken(InstructionTextTokenType.InstructionToken, f"unknown_{opcode}"))
                tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, " "))
                tokens.append(InstructionTextToken(InstructionTextTokenType.FloatingPointToken, str(operand)))
                
            return tokens, 16
        except:
            return None

    def get_instruction_low_level_il(self, data, addr, il):
        if len(data) < 16:
            return None
            
        try:
            opcode, operand = struct.unpack("<Qd", data[:16])
            
            if opcode == 0x0:  # push
                il.append(il.push(8, il.const_float(8, operand)))
            elif opcode == 0x1:  # pop
                il.append(il.pop(8))
            elif opcode == 0x7:  # add
                il.append(il.push(8, il.float_add(8, il.pop(8), il.pop(8))))
            elif opcode == 0x8:  # sub
                il.append(il.push(8, il.float_sub(8, il.pop(8), il.pop(8))))
            elif opcode == 0x9:  # mul
                il.append(il.push(8, il.float_mult(8, il.pop(8), il.pop(8))))
            elif opcode == 0xA:  # div
                il.append(il.push(8, il.float_div(8, il.pop(8), il.pop(8))))
            elif opcode == 0x19:  # jmp
                target = addr + 16 + int(operand) * 16
                il.append(il.jump(il.const(8, target)))
            elif opcode == 0x1A:  # call
                target = int(operand) * 16
                il.append(il.call(il.const(8, target)))
            elif opcode == 0x1B:  # ret
                il.append(il.ret(il.pop(8)))
            else:
                il.append(il.unimplemented())
                
            return 16
        except:
            return None


class BoatVMView(BinaryView):
    name = "BoatVM"
    long_name = "Boat VM Bytecode"

    @classmethod
    def is_valid_for_data(cls, data):
        if len(data) < 16:
            return False
        if len(data) % 16 != 0:
            return False
        
        # Check if first instruction looks valid
        try:
            opcode, operand = struct.unpack("<Qd", data[:16])
            return opcode <= 0x21
        except:
            return False

    def __init__(self, data):
        BinaryView.__init__(self, parent_view=data, file_metadata=data.file)
        self.platform = Architecture["boatvm"].standalone_platform

    def init(self):
        try:
            # Read all instructions
            data = self.parent_view.read(0, len(self.parent_view))
            
            # Create segments
            self.add_auto_segment(0, len(data), 0, len(data), 
                                SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable)
            
            # Add entry point
            self.add_entry_point(0)
            
            return True
        except:
            return False


class BoatVMBinaryViewType(BinaryViewType):
    name = "BoatVM"
    long_name = "Boat VM Bytecode"

    def __init__(self):
        super(BoatVMBinaryViewType, self).__init__()

    @classmethod
    def is_valid_for_data(cls, data):
        return BoatVMView.is_valid_for_data(data)

    def create(self, data):
        return BoatVMView(data)

    def get_load_settings_for_data(self, data):
        return None


# Register architecture and view type
arch = BoatVMArchitecture()
arch.register()

view_type = BoatVMBinaryViewType()
view_type.register()