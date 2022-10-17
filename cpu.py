import struct 
import glob
from elftools.elf.elffile import ELFFile

regfile = [0]*33
PC = 32

# 4K
memory = '\x00' * 0x1000

# fetch instruction
# read register and decode the instruction
# execute
# write the result

def out_section(filename, elf):
    print("In file: ", filename)
    for section in elf.iter_sections():
        print(section.name, sep=" ")


if __name__  == "__main__":
    for x in glob.glob("riscv-tests/isa/rv32ui-p*"):
        if x.endswith(".dump"):
            continue
        with open(x, 'rb') as f:
            e = ELFFile(f)
            text = e.get_section_by_name(".text.init")
            print(x, e, text.data())
            # out_section(x, e)
            exit(0)
