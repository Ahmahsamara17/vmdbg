#!/usr/bin/env python3

import argparse
import sys
import yaml

def load_isa(path):
    
    with open(path, "r") as f:
        isa = yaml.safe_load(f)
    
    vm_name      = isa.get("vm_name", "unknown_vm")
    fields_order  = isa.get("fields_order")
    registers    = isa.get("registers", {})
    instructions = isa.get("instructions", {})

    if not isinstance(fields_order, list) or len(fields_order) != 3:
        raise ValueError("fields_order must be a list of three entries (opcode/arg1/arg2)")
    if "opcode" not in fields_order:
        raise ValueError("fields_order must contain an 'opcode' entry")

    return {
            "vm_name":      vm_name,
            "fields_order": fields_order,
            "registers":    registers,
            "instructions": instructions,
    }


def print_isa_fields(isa_object):
    """
    Pretty print the ISA object fields in a human-readable format.
    """

    vm_name      = isa_object.get("vm_name", "unknown_vm")
    fields_order = isa_object.get("fields_order", [])
    registers    = isa_object.get("registers", {})
    instructions = isa_object.get("instructions", {})

    print(f"VM Name: {vm_name}\n")
    print(f"Fields order: {fields_order}\n")

    print("Registers:")
    if not registers:
        print("  <none>")
    else:
        for byte_str, reg_name in sorted(registers.items()):
            print(f"  {byte_str} -> {reg_name}")
    print()

    print("Instructions:\n")
    if not instructions:
        print("  <none>")
    else:
        for opcode, spec in sorted(instructions.items()):
            mnemonic = spec.get("mnemonic", "<no_mnemonic>")
            enabled  = bool(spec.get("enabled", False))
            length   = spec.get("length", None)
            operands = spec.get("operands", [])

            status = "enabled" if enabled else "disabled"
            if length is not None:
                print(f"  {opcode}: {mnemonic} ({status}, length={length})")
            else:
                print(f"  {opcode}: {mnemonic} ({status}, length=?)")

            if operands:
                for op in operands:
                    name   = op.get("name", "<anon>")
                    kind   = op.get("kind", "byte")
                    source = op.get("source", "arg1")
                    print(f"      - {name}: kind={kind}, source={source}")
            else:
                print("      - <no operands>")
            print()


def load_bytecode(path):
    with open(path, "rb") as f:
        return f.read()


def format_reg(byte_val, reg_map):
    key = f"0x{byte_val:02x}"
    return reg_map.get(key, f"reg_0x{byte_val:02x}")

def decode_one_instr(isa_object, one_instr):
    
    if len(one_instr) != 3:
        return None
    
    b0, b1, b2 = one_instr

    order  = isa_object["fields_order"]
    fields = {}

    fields[order[0]] = b0
    fields[order[1]] = b1
    fields[order[2]] = b2
    
    opcode_byte = fields["opcode"]
    arg1 = fields.get("arg1", 0)
    arg2 = fields.get("arg2", 0)

    opcode_key   = f"0x{opcode_byte:02x}"
    instructions = isa_object["instructions"]

    if opcode_key not in instructions:
        mnemonic = f"UNKNOWN_OPCODE_0x{opcode_byte:02x}"
        op1_str = f"0x{arg1:02x}"
        op2_str = f"0x{arg2:02x}"
        return mnemonic, op1_str, op2_str

    spec     = instructions[opcode_key]
    mnemonic = spec.get("mnemonic", f"OP_0x{opcode_byte:02x}")
    enabled  = bool(spec.get("enabled", False))
    
    if not enabled:
        mnemonic = f"{mnemonic}_UNIMPLIMENTED"
        op1_str = f"0x{arg1:02x}"
        op2_str = f"0x{arg2:02x}"
        return mnemonic, op1_str, op2_str

    operands       = spec.get("operands", [])

    operand_values = []
    
    for operand in operands:
        kind   = operand.get("kind", "byte")
        source = operand.get("source", "arg1")

        if source == "arg1":
            raw = arg1
        elif source == "arg2":
            raw = arg2
        else:
            raw = 0

        if kind == "reg":
            operand_values.append(format_reg(raw, isa_object["registers"]))
        elif kind == "imm":
            operand_values.append(f"0x{raw:02x}")
        else:
            operand_values.append(f"0x{raw:02x}")
        
        if opcode_key == "0x20":  # STM
            if len(operand_values) >= 1 and operand_values[0] and not operand_values[0].startswith("*"):
                operand_values[0] = f"*{operand_values[0]}"

        if opcode_key == "0x01":  # LDM
            if len(operand_values) >= 2 and operand_values[1] and not operand_values[1].startswith("*"):
                operand_values[1] = f"*{operand_values[1]}"

    while len(operand_values) < 2:
        operand_values.append("")

    op1_str = operand_values[0]
    op2_str = operand_values[1]

    return mnemonic, op1_str, op2_str

def disassemble(isa_object, bytecode, start_offset=0, max_instructions=None, outfile_path=None):
    
    length = 3
    size   = len(bytecode)
    offset = start_offset
    count  = 0

    outfile = None
    if outfile_path is not None:
        outfile = open(outfile_path, "w", encoding="utf-8")

    print("VM CODE:\n")

    while offset + length <= size:
        
        if max_instructions is not None and count >= max_instructions:
            break
        
        one_instr = bytecode[offset:offset+length]
        result = decode_one_instr(isa_object, one_instr)
        if result is None:
            break

        mnemonic, op1, op2 = result

        if op1 and op2:
            line = f"{mnemonic}, {op1}, {op2}"
        elif op1:
            line = f"{mnemonic}, {op1},"
        else:
            line = f"{mnemonic},,"

        # print to stdout
        print(f"\t{line}")

        # write to file if requested
        if outfile is not None:
            outfile.write(line + "\n")

        offset += length
        count  += 1

    if outfile is not None:
        outfile.close()
    print()
    return


isa_path      = "vm_isa.yml"
bytecode_path = "yan85.bin"
disasm_path   = "disasm_yan85.txt"

isa_obj  = load_isa(isa_path)
bytecode = load_bytecode(bytecode_path)


print_isa_fields(isa_obj)

disassemble(isa_obj, bytecode, outfile_path=disasm_path)



