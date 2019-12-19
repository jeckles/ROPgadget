import sys
from bfdpie import *
from capstone import *
from capstone.x86 import *
import queue
import IPython
import pefile

# This function is used to determine if an instruction is associated with
def isElem(d, tar):
    for k in d.keys():
        if int(k) == tar:
            return d[k]
    return False


def isMem(keys, tar):
    for k in keys:
        if int(k) == tar:
            return True
    return False

# control flow
def isCFlow(groups):
    if len(groups) > 0:
        for g in groups:
            if (g == CS_GRP_JUMP or g == CS_GRP_CALL or CS_GRP_RET or CS_GRP_IRET):
                return True
    return False

def isUnconditionalCSFlow(ins):
    return (ins.id == X86_INS_JMP or ins.id == X86_INS_LJMP or ins.id == X86_INS_RET or ins.id == X86_INS_RETF or ins.id == X86_INS_RETFQ) 

# This function is used to get the immediate target operand of the control
# flow instruction passed in. 
def insTarget(ins):
    # Get the operands of the instruction
    if len(ins.operands) > 0:
        for op in ins.operands:
            # We only want the immediate control flow targets
            if (op.type == X86_OP_IMM):
                # Return the immediate control flow target
                return op.value.imm
    # If no immediate control flow target, return 0
    return 0

def isRetIns(ins):
    if ins.id == X86_INS_RET == True:
        return True
    else:
        return False


def find_gadgets_at_root(sec, root, gadgets, md, bit):
    max_gadget_len = 0
    max_ins_bytes = 0

    if bit == 32:
        max_gadget_len = 3
        max_ins_bytes = 9
    else: 
        max_gadget_len = 5
        max_ins_bytes = 15

    root_offset = max_gadget_len * max_ins_bytes
    
    a = root - 1
    while (a >= root - root_offset and a >= 0):
        addr = a
        offset = addr - sec.vma
        length = 0
        gadget_str = ""
        for ins in md.disasm(sec.contents[offset:], addr):
            if (ins.id == X86_INS_INVALID or ins.size == 0):
                break
            elif (ins.address > root):
                break
            elif (isCFlow(ins.groups) and not isRetIns(ins)):
                break
            else:
                length = length + 1
                if (length > max_gadget_len):
                    break

            gadget_str += str(ins.mnemonic) + " " + str(ins.op_str)

            # print("root 0x%x insaddr 0x%x" %(root, ins.address))

            if(ins.address == root):
                if gadget_str in gadgets.keys():
                    gadgets[gadget_str].append(hex(a))
                else:
                    gadgets[gadget_str] = []
                    gadgets[gadget_str].append(hex(a))
                break
            gadget_str += "; "
        a = a - 1
    return 0


def find_gadgets(md, bit, sec):
    # This is the dictionary that will hold our gadgets
    gadgets = {}

    # This is the opcode of a ret instruction
    ret_opc = 0xc3

    contents = bytearray(sec.contents)
    
    # These are the bytes of the section we're working with
    i = 0
    while (i < len(contents)):
        if contents[i] == ret_opc:
            # For testing purposes 
            if (find_gadgets_at_root(sec, i, gadgets, md, bit) < 0):
                break
        i += 1


    # Now, need to loop and print the ROP gadget as well as its address
    for k in gadgets.keys():
        # First, print the gadget
        print("%s\t%s" %(gadgets[k], k))
    
def main():
    # Check that a binary is input
    if len(sys.argv) < 2:
        sys.exit("No binary to disassemble.")

    is_pe = False 
    # This is how we check if the file is a PE binary
    pe_check = open(sys.argv[1], 'rb')
    pe = 0
    if pe_check.read(2) == "MZ":
        pe = pefile.PE(sys.argv[1])
        is_pe = True

    # Load the binary passed in as a Binary
    bin = Binary(sys.argv[1])

    bit = 0

    if bin.arch.bits == 32:
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        bit = 32
    elif bin.arch.bits == 64:
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        bit = 64
    md.detail = True


    if is_pe == False:
        for index, sec in bin.sections.iteritems():
            if sec.flags & bfdpie.SEC_CODE:
                find_gadgets(md, bit, sec)
    else: 
        for section in pe.sections:
            find_gadgets(md, bit, sec)

if __name__ == "__main__":
    main()

