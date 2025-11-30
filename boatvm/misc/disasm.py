import struct

pc_max = 0x1762
instructions = []

with open("./loaded_program.bin", "rb") as f:
    prog = f.read()
    for i in range(pc_max):
        instructions.append(struct.unpack("<Qd", prog[i * 16 : (i + 1) * 16]))

for i, (opcode, operand) in enumerate(instructions):
    print(f"{i:04x}: ", end="")

    if opcode == 0x0:
        print(f"push {operand}", end="")
        if int(operand) == operand and operand > 31 and operand < 128:
            print(f"     ; {chr(int(operand))}", end="")
    elif opcode == 0x1:
        print("pop", end="")
    elif opcode == 0x2:
        print("dup", end="")
    elif opcode == 0x3:
        print("dup2", end="")
    elif opcode == 0x4:
        print("rot3", end="")
    elif opcode == 0x5:
        print("swap", end="")

    elif opcode == 0x6:
        print("nop", end="")

    elif opcode == 0x7:
        print("add", end="")
    elif opcode == 0x8:
        print("sub", end="")
    elif opcode == 0x9:
        print("mul", end="")
    elif opcode == 0xA:
        print("div", end="")

    elif opcode == 0x10:
        print("min", end="")
    elif opcode == 0x11:
        print("max", end="")

    elif opcode == 0xB:
        print("floor", end="")
    elif opcode == 0xC:
        print("ceiling", end="")
    elif opcode == 0xD:
        print("trunc", end="")
    elif opcode == 0xE:
        print("round", end="")
    elif opcode == 0xF:
        print("abs", end="")

    elif opcode == 0x12:
        print("clear_flags", end="")

    elif opcode == 0x13:
        print(f"jmp_div0 pc+{int(operand)}", end="")
    elif opcode == 0x14:
        print(f"jmp_prec pc+{int(operand)}", end="")
    elif opcode == 0x15:
        print(f"jmp_inv pc+{int(operand)}", end="")
    elif opcode == 0x16:
        print(f"jmp_of pc+{int(operand)}", end="")
    elif opcode == 0x17:
        print(f"jmp_uf pc+{int(operand)}", end="")
    elif opcode == 0x18:
        print(f"jmp_anyf pc+{int(operand)}", end="")
    elif opcode == 0x19:
        print(f"jmp pc+{int(operand)}", end="")

    elif opcode == 0x1A:
        print(f"call {int(operand)}", end="")
    elif opcode == 0x1B:
        print("ret", end="")

    elif opcode == 0x1C:
        print("print_double", end="")
    elif opcode == 0x1D:
        print("putc", end="")
    elif opcode == 0x1E:
        print("read_double", end="")
    elif opcode == 0x1F:
        print("getc", end="")

    elif opcode == 0x20:
        print("load", end="")
    elif opcode == 0x21:
        print("store", end="")

    else:
        print(f"<unknown op {opcode} : {operand}>", end="")

    print()
