#!/usr/bin/env python3

import sys
import struct
import yaml


def load_isa(path):
    with open(path, "r") as f:
        isa = yaml.safe_load(f)

    vm_name      = isa.get("vm_name", "unknown_vm")
    fields_order = isa.get("fields_order")
    registers    = isa.get("registers", {})
    instructions = isa.get("instructions", {})

    if not isinstance(fields_order, list) or len(fields_order) != 2:
        raise ValueError("fields_order must be a list of two entries (opcode/data)")
    if "opcode" not in fields_order:
        raise ValueError("fields_order must contain an 'opcode' entry")

    return {
        "vm_name":      vm_name,
        "fields_order": fields_order,
        "registers":    registers,
        "instructions": instructions,
    }


def print_isa_fields(isa_object):
    vm_name      = isa_object["vm_name"]
    fields_order = isa_object["fields_order"]
    registers    = isa_object["registers"]
    instructions = isa_object["instructions"]

    print(f"VM ISA: {vm_name}")
    print(f"  fields_order: {fields_order}")
    print()

    if registers:
        print("Registers:")
        for key, name in registers.items():
            print(f"  {key}: {name}")
        print()
    else:
        print("Registers: <none>")
        print()

    print("Instructions:")
    for opcode, spec in instructions.items():
        if not isinstance(spec, dict):
            continue

        mnemonic = spec.get("mnemonic", "<no_mnemonic>")
        enabled  = bool(spec.get("enabled", False))
        operands = spec.get("operands", [])

        status = "enabled" if enabled else "disabled"
        print(f"  {opcode}: {mnemonic} ({status})")

        if operands:
            for op in operands:
                name   = op.get("name", "<anon>")
                kind   = op.get("kind", "imm")
                source = op.get("source", "data")
                print(f"      - {name}: kind={kind}, source={source}")
        else:
            print("      - <no operands>")
        print()


def load_bytecode(path):
    with open(path, "rb") as f:
        return f.read()


def instr_uses_data(spec):
    operands = spec.get("operands", [])
    for op in operands:
        if op.get("source", "data") == "data":
            return True
    return False


def format_immediate(value):
    rounded = round(value)
    if abs(value - rounded) < 1e-9:
        return str(int(rounded))
    return repr(value)


def decode_one_instr(isa_object, words, word_index):
    """
    Decode one instruction starting at words[word_index].

    Returns:
        (consumed_words, mnemonic, op1_str, op2_str)
    or:
        None on fatal/truncated input.
    """
    instructions = isa_object["instructions"]

    if word_index >= len(words):
        return None

    opcode_word = words[word_index]
    rounded     = round(opcode_word)
    if abs(opcode_word - rounded) > 1e-9:
        mnemonic = f"BAD_OPCODE_{opcode_word!r}"
        return 1, mnemonic, "", ""

    opcode_int = int(rounded)
    key        = f"0x{opcode_int:02x}"

    spec = instructions.get(key)
    if spec is None:
        mnemonic = f"OP_0x{opcode_int:02x}"
        return 1, mnemonic, "", ""

    mnemonic = spec.get("mnemonic", f"OP_0x{opcode_int:02x}")
    enabled  = bool(spec.get("enabled", False))
    if not enabled:
        mnemonic = f"{mnemonic}_DISABLED"

    uses_data = instr_uses_data(spec)
    op1_str   = ""
    op2_str   = ""
    consumed  = 1

    if uses_data:
        if word_index + 1 >= len(words):
            # truncated immediate
            mnemonic = f"{mnemonic}_TRUNC"
            return 1, mnemonic, "", ""

        data_word = words[word_index + 1]
        operands  = spec.get("operands", [])

        # This VM only ever has at most one immediate operand
        if operands:
            op_spec = operands[0]
            kind    = op_spec.get("kind", "imm")

            if kind == "imm":
                op1_str = format_immediate(data_word)
            else:
                op1_str = format_immediate(data_word)

        consumed = 2

    return consumed, mnemonic, op1_str, op2_str


def disassemble(isa_object, bytecode, start_word_index=0, max_instructions=None, outfile_path=None):
    # Convert raw bytes into a list of little-endian doubles
    if len(bytecode) % 8 != 0:
        print(f"[!] Bytecode size {len(bytecode)} is not a multiple of 8 bytes", file=sys.stderr)

    words = []
    for i in range(0, len(bytecode), 8):
        if i + 8 > len(bytecode):
            break
        (val,) = struct.unpack_from("<d", bytecode, i)
        words.append(val)

    total_words = len(words)
    idx         = start_word_index
    count       = 0

    outfile = None
    if outfile_path is not None:
        outfile = open(outfile_path, "w", encoding="utf-8")

    print("VM CODE:\n")

    while idx < total_words:
        if max_instructions is not None and count >= max_instructions:
            break

        result = decode_one_instr(isa_object, words, idx)
        if result is None:
            break

        consumed, mnemonic, op1, op2 = result

        if consumed <= 0:
            break

        if op1 and op2:
            line = f"{mnemonic}, {op1}, {op2}"
        elif op1:
            line = f"{mnemonic}, {op1},"
        else:
            line = f"{mnemonic},,"

        print(f"\t{line}")

        if outfile is not None:
            outfile.write(line + "\n")

        idx   += consumed
        count += 1

    if outfile is not None:
        outfile.close()

    print()
    return


isa_path      = "vm_isa.yml"
bytecode_path = "float_program.bin"
disasm_path   = "disasm_boat_vm.txt"

isa_obj  = load_isa(isa_path)
bytecode = load_bytecode(bytecode_path)

print_isa_fields(isa_obj)
disassemble(isa_obj, bytecode, outfile_path=disasm_path)

