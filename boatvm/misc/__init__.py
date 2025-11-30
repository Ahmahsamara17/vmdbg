import struct
from binaryninja import *

print("[BoatVM] Plugin loading...")

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
            
            opcodes = {
                0x0: "push", 0x1: "pop", 0x2: "dup", 0x3: "dup2", 0x4: "rot3", 0x5: "swap",
                0x6: "nop", 0x7: "add", 0x8: "sub", 0x9: "mul", 0xA: "div", 0xB: "floor",
                0xC: "ceiling", 0xD: "trunc", 0xE: "round", 0xF: "abs", 0x10: "min",
                0x11: "max", 0x12: "clear_flags", 0x1B: "ret", 0x1C: "print_double", 
                0x1D: "putc", 0x1E: "read_double", 0x1F: "getc", 0x20: "load", 0x21: "store"
            }
            
            if opcode in opcodes:
                tokens.append(InstructionTextToken(InstructionTextTokenType.InstructionToken, opcodes[opcode]))
                if opcode == 0x0:  # push
                    tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, " "))
                    tokens.append(InstructionTextToken(InstructionTextTokenType.FloatingPointToken, str(operand)))
                    if int(operand) == operand and 31 < operand < 128:
                        tokens.append(InstructionTextToken(InstructionTextTokenType.CommentToken, f"     ; {chr(int(operand))}"))
            elif opcode in [0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19]:  # jumps
                jump_names = {0x13: "jmp_div0", 0x14: "jmp_prec", 0x15: "jmp_inv", 
                             0x16: "jmp_of", 0x17: "jmp_uf", 0x18: "jmp_anyf", 0x19: "jmp"}
                tokens.append(InstructionTextToken(InstructionTextTokenType.InstructionToken, jump_names[opcode]))
                tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, " "))
                target = addr + 16 + int(operand) * 16
                tokens.append(InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, hex(target), target))
            elif opcode == 0x1A:  # call
                tokens.append(InstructionTextToken(InstructionTextTokenType.InstructionToken, "call"))
                tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, " "))
                target = int(operand) * 16
                tokens.append(InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, hex(target), target))
            else:
                tokens.append(InstructionTextToken(InstructionTextTokenType.InstructionToken, f"unknown_{opcode:02x}"))
                tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, " "))
                tokens.append(InstructionTextToken(InstructionTextTokenType.FloatingPointToken, str(operand)))
                
            return tokens, 16
        except:
            return None


class BoatVMView(BinaryView):
    name = "BoatVM"
    long_name = "Boat VM Bytecode"

    @classmethod
    def is_valid_for_data(cls, data):
        print(f"[BoatVM] Checking file validity (size: {len(data)})")
        if len(data) < 16:
            return False
        if len(data) % 16 != 0:
            return False
        
        # Check if first few instructions look valid
        try:
            for i in range(min(3, len(data) // 16)):
                opcode, operand = struct.unpack("<Qd", data[i*16:(i+1)*16])
                if opcode > 0x21:
                    print(f"[BoatVM] Invalid opcode 0x{opcode:x} at instruction {i}")
                    return False
            print(f"[BoatVM] File appears to be valid BoatVM bytecode")
            return True
        except Exception as e:
            print(f"[BoatVM] Error checking validity: {e}")
            return False

    def __init__(self, data):
        print("[BoatVM] Initializing BoatVMView")
        BinaryView.__init__(self, parent_view=data, file_metadata=data.file)
        self.platform = Architecture["boatvm"].standalone_platform

    def init(self):
        print("[BoatVM] Initializing binary view")
        try:
            data = self.parent_view.read(0, len(self.parent_view))
            
            self.add_auto_segment(0, len(data), 0, len(data), 
                                SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable)
            
            self.add_entry_point(0)
            print("[BoatVM] Successfully initialized")
            
            return True
        except Exception as e:
            print(f"[BoatVM] Error in init: {e}")
            return False


class BoatVMBinaryViewType(BinaryViewType):
    name = "BoatVM"
    long_name = "Boat VM Bytecode"

    @classmethod
    def is_valid_for_data(cls, data):
        return BoatVMView.is_valid_for_data(data)

    def create(self, data):
        return BoatVMView(data)


# Register everything
try:
    print("[BoatVM] Registering architecture...")
    BoatVMArchitecture.register()
    
    print("[BoatVM] Registering view type...")  
    BoatVMBinaryViewType.register()
    
    print("[BoatVM] Plugin registered successfully!")
except Exception as e:
    print(f"[BoatVM] Registration error: {e}")
    import traceback
    traceback.print_exc()