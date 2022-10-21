import struct 
import glob
from elftools.elf.elffile import ELFFile

regfile = [0]*33
PC = 32

# 64K at 0x80000000
memory = b'\x00' * 0x10000

from enum import Enum
class Ops(Enum):
    LUI   = 0b0110111  
    AUIPC = 0b0010111
    JAL   = 0b1101111
    JALR  = 0b1100111

    BEQ = BNE = BLT = BGE = BLTU = BGEU = 0b1100011
    LB = LH = LW = LBU = LHU = 0b0000011 
    SB = SH = SW = 0b0100011
    
    ADDI = SLTI = SLTIU = XORI = ORI = ANDI = SLLI = SRLI = SRAI = 0b0010011
    ADD = SLT = SLTU = XOR = OR = AND = SLL = SRL = SRA = SUB = 0b0110011

    FENCE = 0b0001111
    ECALL = EBREAK = 0b1110011


# write segment
def ws(dat, addr):
    global memory
    print(hex(addr), len(dat))
    addr -= 0x80000000
    assert addr >= 0 and addr < len(memory)           
    memory = memory[:addr] + dat + memory[addr+len(dat):]


# parse 32 bit instruction
def r32(addr):
    global memory
    addr -= 0x80000000
    # check addres validity
    assert addr >= 0 and addr < len(memory)           
    return struct.unpack("<I", memory[addr:addr+4])[0]


def dump():
    pp = []
    for i in range(32):
        if i != 0 and i % 8 == 0:
            pp +="\n"
        pp += " %3s: +%08x" % ("x%d" % i, regfile[i])
    pp += "\n PC: %08x" % regfile[PC]
    print(''.join(pp))


def gibi(ins, s, e):
    return (ins >> e) & ((1 << (s-e+1)) - 1)


def step():
    # fetch instruction
    ins = r32(regfile[PC])

    # Instruction decode
    opcode = Ops(gibi(ins, 6, 0))
    print("%x %8x %r" % (regfile[PC], ins, opcode))
    
    if opcode == Ops.JAL:
        rd = gibi(ins, 11, 7)
        assert rd == 0
        # offset 
        imm_j = gibi(ins, 31, 30) << 20 | gibi(ins, 30, 21) << 1 | gibi(ins, 21, 20) << 11 | gibi(ins, 20, 12) << 12
        regfile[PC] += imm_j
        return True


    # execute
    # write the result
    dump()
    return False


def out_section(filename, elf):
    print("In file: ", filename)
    for section in elf.iter_sections():
        print(section.name, sep=" ")


if __name__  == "__main__":
    for x in glob.glob("riscv-tests/isa/rv32ui-v-add"):
        if x.endswith(".dump"):
            continue
        with open(x, 'rb') as f:
            print("test", x)
            e = ELFFile(f)
            for s in e.iter_segments():
                # PAY ATTENTION ON PT_LOAD
                if s.header.p_type == 'PT_LOAD':
                    ws(s.data(), s.header.p_paddr)
            regfile[PC] = 0x80000000
            while step():
                pass
            break

