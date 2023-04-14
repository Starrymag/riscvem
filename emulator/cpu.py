from os import register_at_fork
import re
import struct
import glob
from elftools.elf.elffile import ELFFile
from enum import Enum

# set programm counter to 32
# 32 - index in Regfile
PC = 32

regnames = ["zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1"] +\
            ["a%d" % i for i in range(8)] +\
            ["s%d" % i for i in range(2, 12)] +\
            ["t3", "t4", "t5", "t6", "PC"]

# 64K at 0x80000000
memory = b'\x00' * 0x10000


# class to handle all registers
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


# create register file
regfile = Regfile()


def reset():
    global regfile, memory
    # 64K at 0x80000000
    memory = b'\x00' * 0x10000
    regfile = Regfile()


# all opcodes of rv32ui
class Ops(Enum):
    LUI = 0b0110111  # U type
    AUIPC = 0b0010111  # U type
    JAL = 0b1101111  # J type
    JALR = 0b1100111  # I type

    BRANCH = 0b1100011  # B type
    LOAD = 0b0000011  # also I type, but load
    STORE = 0b0100011  # S type

    IMM = 0b0010011  # I type
    OP = 0b0110011  # R type

    MISC = 0b0001111
    SYSTEM = 0b1110011  # also I type


# all funct3 field codes
class Funct3(Enum):
    ADD = ADDI = SUB = 0b000
    SLLI = SLL = 0b001
    SLTI = SLT = 0b010
    SLTIU = SLTU = 0b011

    XORI = XOR = 0b100
    SRLI = SRL = SRAI = SRA = 0b101
    ORI = OR = 0b110
    ANDI = AND = 0b111

    BEQ = 0b000
    BNE = 0b001
    BLT = 0b100
    BGE = 0b101
    BLTU = 0b110
    BGEU = 0b111

    ECALL = 0b000
    CSRRW = 0b001
    CSRRS = 0b010
    CSRRC = 0b011
    CSRRWI = 0b101
    CSRRSI = 0b110
    CSRRCI = 0b111


# all Funct7 field codes
class Funct7(Enum):
    ADD = XOR = OR = AND = SLL = SRL = SLT = SLTU = 0b0000000
    SUB = SRA = 0b0100000


# write segment
def ws(dat: bytes, addr: int) -> None:
    global memory
    # print(hex(addr), len(dat))
    addr -= 0x80000000
    assert addr >= 0 and addr < len(memory)
    memory = memory[:addr] + dat + memory[addr+len(dat):]


# parse 32 bit instruction
def r32(addr: int) -> tuple:
    global memory
    addr -= 0x80000000
    # check addres validity
    if addr < 0 or addr > len(memory) - 4:
        raise Exception("read out of bound: 0x%x" % addr)
    return struct.unpack("<I", memory[addr:addr+4])[0]


# dump regs values from regfile
def dump() -> None:
    pp = []
    for i, name in enumerate(regnames):
        if i != 0 and i % 8 == 0:
            pp += "\n"
        pp += " %4s: +%08x" % (name, regfile[i])
    # pp += "\n PC: %08x" % regfile[PC]
    print(''.join(pp))


# encode num as sign extended
def sign_extend(num: int, length: int) -> int:
    # check first bit
    if num >> (length - 1) == 1:
        return - ((1 << length) - num)
    else:
        return num


def arithmetic(x: int, y: int, funct3: Funct3, rev=0) -> int:
    if funct3 == Funct3.ADDI:
        return x + y
    elif funct3 == Funct3.SRLI:
        y &= 0x1f
        # SRAI
        if rev:
            sign_bit = x >> 31
            res = x >> y
            res = (0xFFFFFFFF * sign_bit) << (32 - y) | res
            return res
        else:
            return x >> y
    elif funct3 == Funct3.SLLI:
        return x << (y&0x1f)
    elif funct3 == Funct3.ORI:
        return x | y
    elif funct3 == Funct3.ANDI:
        return x & y
    elif funct3 == Funct3.XORI:
        return x ^ y
    else:
        raise Exception("write %r" % funct3)


# execute one cpu cycle
def step() -> bool:
    # fetch instruction
    ins = r32(regfile[PC])

    def gibi(s, e):
        """
        return bits from s to e inclusive
        s - start index
        e - end index
        """
        return (ins >> e) & ((1 << (s-e+1)) - 1)

    # Instruction decode
    opcode = Ops(gibi(6, 0))

    # print("%x %8x %r" % (regfile[PC], ins, opcode))
    # dump()

    # execute
    if opcode == Ops.JAL:
        # J-type instruction
        rd = gibi(11, 7)
        # calculate offset
        imm_j = sign_extend(((gibi(32, 31) << 20) | (gibi(30, 21) << 1) |
                            (gibi(21, 20) << 11) | (gibi(19, 12) << 12)), 21)
        regfile[rd] = regfile[PC] + 4
        regfile[PC] += imm_j
        return True

    if opcode == Ops.JALR:
        # I-type instruction
        rd = gibi(11, 7)
        rs1 = gibi(19, 15)
        imm_i = sign_extend(gibi(31, 20), 12)
        offset = regfile[rs1] + imm_i
        # set lsb to zero
        offset = (offset // 2) * 2
        regfile[rd] = regfile[PC] + 4
        regfile[PC] = offset
        return True

    elif opcode == Ops.IMM:
        # I-type instruction
        funct3 = Funct3(gibi(14, 12))
        rd = gibi(11, 7)
        rs1 = gibi(19, 15)
        imm_i = sign_extend(gibi(31, 20), 12)
        funct7 = gibi(31, 25)
        # for SRAI
        rev = funct7 == 0b0100000
        regfile[rd] = arithmetic(regfile[rs1], imm_i, funct3, rev)
        regfile[PC] += 4
        return True

    elif opcode == Ops.AUIPC:
        # U-type of instruction
        rd = gibi(11, 7)
        imm_u = gibi(31, 12)
        # PAY ATTENTION to bit shift
        imm_u = imm_u << 12
        # print("Dist: x%x IMM: %x" % (rd, imm_u))
        regfile[rd] = regfile[PC] + imm_u
        regfile[PC] += 4
        return True

    elif opcode == Ops.LUI:
        # U-type
        rd = gibi(11, 7)
        imm_u = gibi(31, 12)
        # PAY ATTENTION to bit shift
        imm_u = imm_u << 12
        regfile[rd] = imm_u
        regfile[PC] += 4
        return True

    elif opcode == Ops.SYSTEM:
        funct3 = Funct3(gibi(14, 12))
        rd = gibi(11, 7)
        rs1 = gibi(19, 15)
        csr = gibi(31, 20)
        if funct3 == Funct3.CSRRW:
            # print("CSRRW", regfile[3], csr)
            pass
        if funct3 == Funct3.CSRRC:
            # print("CSRRC", regfile[3], csr)
            pass

        elif funct3 == Funct3.ECALL:
            print("ecall", regfile[3], csr)
            if regfile[regnames.index("a7")] == 93:
                if regfile[regnames.index("a0")] == 0:
                    print("Test passed")
                    return False
                else:
                    raise Exception("ERROR IN TEST - %d" % regfile[regnames.index("gp")])
            else:
                pass
                # raise Exception("Unknown SYSCALL")
        else:
            # raise Exception("more CSRs funct3: %r - %s" % (funct3, bin(funct3.value)))
            pass

    elif opcode == Ops.MISC:
        pass

    elif opcode == Ops.BRANCH:
        # B-type of instruction
        funct3 = Funct3(gibi(14, 12))
        rs1 = gibi(19, 15)
        rs2 = gibi(24, 20)
        offset = sign_extend((gibi(32, 31) << 12) | (gibi(30, 25) << 5)
                             | (gibi(11, 8) << 1) | (gibi(8, 7) << 11), 13)
        cond = False
        if funct3 == Funct3.BEQ:
            cond = regfile[rs1] == regfile[rs2]
        elif funct3 == Funct3.BNE:
            cond = regfile[rs1] != regfile[rs2]
        elif funct3 == Funct3.BLT:
            cond = sign_extend(regfile[rs1], 32) < sign_extend(regfile[rs2], 32)
        elif funct3 == Funct3.BLTU:
            cond = regfile[rs1] < regfile[rs2]
        elif funct3 == Funct3.BGE:
            cond = sign_extend(regfile[rs1], 32) >= sign_extend(regfile[rs2], 32)
        elif funct3 == Funct3.BGEU:
            cond = regfile[rs1] >= regfile[rs2]
        else:
            raise Exception("wirte funct3 %r" % funct3)
        if cond:
            regfile[PC] += offset
            return True

    elif opcode == Ops.LOAD:
        # I-type
        rd = gibi(11, 7)
        rs1 = gibi(19, 15)
        funct3 = Funct3(gibi(14, 12))
        imm_i = sign_extend(gibi(31, 20), 12)
        addr = regfile[rs1] + imm_i
        print("LOAD %8x" % addr)

    elif opcode == Ops.STORE:
        # S type
        rs1 = gibi(19, 15)
        rs2 = gibi(24, 20)
        funct3 = gibi(14, 12)
        imm_s = sign_extend(((gibi(31, 25) << 5) | gibi(11, 7)), 12)
        addr = rs1 + imm_s
        value = regfile[rs2]
        print("STORE %8x = %x" % (addr, value))

    elif opcode == Ops.OP:
        # R-type
        rd = gibi(11, 7)
        rs1 = gibi(19, 15)
        rs2 = gibi(24, 20)
        funct3 = Funct3(gibi(14, 12))
        funct7 = Funct7(gibi(31, 25))
        if funct3 == Funct3.ADD and funct7 == Funct7.ADD:
            regfile[rd] = regfile[rs1] + regfile[rs2]
        elif funct3 == Funct3.OR and funct7 == Funct7.OR:
            regfile[rd] = regfile[rs1] | regfile[rs2]
        else:
            raise Exception("wirte funct3 %r, funct7 %r" % (funct3, funct7))
    else:
        dump()
        raise Exception("unknown opcode: %r" % opcode)

    # write the result
    regfile[PC] += 4
    return True


def out_section(filename, elf):
    print("In file: ", filename)
    for section in elf.iter_sections():
        print(section.name, sep=" ")


if __name__ == "__main__":
    for x in glob.glob("riscv-tests/isa/rv32ui-p-*"):
        reset()
        if x.endswith(".dump"):
            continue
        with open(x, 'rb') as f:
            print("test", x)
            # print("LOADED SEGMENTS:")
            e = ELFFile(f)
            for s in e.iter_segments():
                # PAY ATTENTION ON PT_LOAD
                if s.header.p_type == 'PT_LOAD':
                    ws(s.data(), s.header.p_paddr)
            regfile[PC] = 0x80000000
            # print("\nSTART SIMULATING")
            while step():
                pass
            # break
