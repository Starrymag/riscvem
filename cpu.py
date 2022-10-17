import struct 
import glob
from elftools.elf.elffile import ELFFile

regfile = [0]*33
PC = 32

# 64K at 0x80000000
memory = b'\x00' * 0x10000


def ws(dat, addr):
    global memory
    print(hex(addr), len(dat), len(memory))
    addr -= 0x80000000
    assert addr >= 0 and addr < len(memory)           
    memory = memory[:addr] + dat + memory[addr+len(dat):]


# parse 32 bit instruction
def r32(addr):
    global memory
    addr -= 0x80000000
    # check addres validity
    assert addr >= 0 and addr < len(memory)           
    return struct.unpack("I", memory[addr:addr+4])[0]

def dump():
    pp = []
    for i in range(32):
        if i != 0 and i % 8 == 0:
            pp +="\n"
        pp += " %3s: +%08x" % ("x%d" % i, regfile[i])
    pp += "\n PC: %08x" % regfile[PC]
    print(''.join(pp))


def step():
    # fetch instruction
    ins = r32(regfile[PC])
    
    # read register and decode the instruction
    dump()

    # execute
    # write the result
    return False


def out_section(filename, elf):
    print("In file: ", filename)
    for section in elf.iter_sections():
        print(section.name, sep=" ")


if __name__  == "__main__":
    for x in glob.glob("riscv-tests/isa/rv32ui-*"):
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
