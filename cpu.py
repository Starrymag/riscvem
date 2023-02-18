import struct
import glob
from elftools.elf.elffile import ELFFile
from enum import Enum

regfile = [0]*33
PC = 32

# 64K at 0x80000000
memory = b'\x00' * 0x10000


class Regfile:
    def __init__(self):
        self.regs = [0]*33

    def __getitem__(self, key):
        return self.regs[key]

    def __setitem__(self, key, value):
        # dont write to x0 register
        if key == 0:
            return
        self.regs[key] = value & 0xFFFFFFFF


class Ops(Enum):
    LUI    = 0b0110111  # U type
    AUIPC  = 0b0010111  # U type
    JAL    = 0b1101111  # J type
    JALR   = 0b1100111  # I type

    BRANCH = 0b1100011  # B type 
    LOAD   = 0b0000011  # also I type, but load
    STORE  = 0b0100011  # S type

    IMM    = 0b0010011  # I type
    OP     = 0b0110011  # R type

    MISC  = 0b0001111   # 
    ECALL  = EBREAK = 0b1110011  # also I type


class Funct3(Enum):
    ADD = ADDI = SUB = 0b000
    SLLI = SLL = 0b001
    SLTI = SLT = 0b010
    SLTIU = SLTU = 0b011

    XORI = XOR = 0b100
    SRLI = SRL = SRAI = SRA = 0b101
    ORI = OR = 0b110
    ANDI = AND = 0b111


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
            pp += "\n"
        pp += " %3s: +%08x" % ("x%d" % i, regfile[i])
    pp += "\n PC: %08x" % regfile[PC]
    print(''.join(pp))


def sign_extend(num, length):
    if num >> (length - 1) == 1:
        return - ((1 << length) - num)
    else:
        return num


def step():
    # fetch instruction
    ins = r32(regfile[PC])

    def gibi(s, e):
        return (ins >> e) & ((1 << (s-e+1)) - 1)

    # Instruction decode
    opcode = Ops(gibi(6, 0))
    print("%x %8x %r" % (regfile[PC], ins, opcode))
    if opcode == Ops.JAL:
        # J-type instruction
        rd = gibi(11, 7)
        assert rd == 0
        # calculate offset
        imm_j = gibi(31, 30) << 20 | gibi(30, 21) << 1 | gibi(21, 20) << 11 | \
            gibi(20, 12) << 12
        regfile[PC] += imm_j
        return True
    elif opcode == Ops.IMM:
        # I-type instruction
        funct3 = Funct3(gibi(14, 12))
        rd = gibi(11, 7)
        rs1 = gibi(19, 15)
        # TODO Use sign extend
        imm_i = gibi(31, 20)
        if funct3 == Funct3.ADDI:
            regfile[rd] = regfile[rs1] + imm_i
        else:
            raise Exception("write %r" % funct3)
        regfile[PC] += 4
        return True
    elif opcode == Ops.AUIPC:
        # U-type of instruction
        rd = gibi(11, 7)
        imm_u = gibi(31, 12)
        print("Dist: x%x IMM: %x" % (rd, imm_u))
        regfile[rd] = regfile[PC] + imm_u

    # execute
    # write the result
    dump()
    return False


def out_section(filename, elf):
    print("In file: ", filename)
    for section in elf.iter_sections():
        print(section.name, sep=" ")


if __name__ == "__main__":
    for x in glob.glob("riscv-tests/isa/rv32ui-v-add"):
        if x.endswith(".dump"):
            continue
        with open(x, 'rb') as f:
            print("test", x)
            print("LOADED SEGMENTS:")
            e = ELFFile(f)
            for s in e.iter_segments():
                # PAY ATTENTION ON PT_LOAD
                if s.header.p_type == 'PT_LOAD':
                    ws(s.data(), s.header.p_paddr)
            regfile[PC] = 0x80000000
            print("\nSTART SIMULATING")
            while step():
                pass
            break
