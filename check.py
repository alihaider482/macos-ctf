#!/usr/bin/env python3

TARGET = 0xd98851cb

def emulate_check(core: str) -> int:
    """
    Recreates the core checksum loop from the binary.
    Returns the final w13 value.
    """
    w9 = 0xc419 | (0x76d << 16)
    w10 = 0x8832 | (0xedb << 16)
    w11 = 0x4190 | (0x76dc << 16)
    w12 = 0x8320 | (0xedb8 << 16)

    w13 = 0
    x8 = 0
    x20 = len(core)

    while x8 != x20:
        b = ord(core[x8])
        w13 ^= b
        w14 = (w13 & 1) & w9
        w15 = ((w13 << 30) & 0xffffffff) & w10
        w15 ^= (w13 >> 6)
        w13 = (w15 ^ w14) & 0xffffffff
        x8 += 1

    return w13

def check_flag(flag: str) -> bool:
    if not (flag.startswith("BHFlagY{") and flag.endswith("}")):
        return False
    if len(flag) != 36:
        return False
    core = flag[7:-1]
    return emulate_check(core) == TARGET

if __name__ == "__main__":
    # Try brute-forcing over printable ASCII just to test
    import string, itertools
    charset = string.ascii_letters + string.digits + "_{}-!@#$%^&*"
    print("Testing brute-force… (will stop at first match)")
    for candidate in itertools.product(charset, repeat=3):  # just demo small length
        test_core = "".join(candidate).ljust(27, "A")  # pad to length 27
        if emulate_check(test_core) == TARGET:
            print("FOUND candidate core:", test_core)
            print("Flag:", f"BHFlagY{{{test_core}}}")
            break
