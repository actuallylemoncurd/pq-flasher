#!/usr/bin/env python3
import struct
from argparse import ArgumentParser
import crcmod

# fmt: off

# (addr, orig, new (optional) )
patches = {
    "2501": [
        (0x0005E7A8, b"1K0909144E \x002501", b"1K0909144E \x002502"),  # Software number and version
        (0x0005E221, b"\x64", b"\x00"),  # Disengage countdown
        (0x0005E283, b"\x32", b"\x00"),  # Min speed
        (0x0005FFFC, b"Ende", b"\xff\xff\xff\xff"),  # End of FW marker
    ],
    "3501": [
        (0x0005D828, b"1K0909144R \x003501", b"1K0909144R \x003502"),  # Software number and version
        (0x0005D289, b"\x64", b"\x00"),  # Disengage countdown
        (0x0005D2FA, b"\x14", b"\x00"),  # Min speed

        # Custom steering maps, switchable with DCC??

        # 1: normal golf / NMS         normal (dont need to edit this one, commented it out)
        # 2: mobility, floaty steer!   comfort
        # 3: TTRS/RS3, sporty!!        sport

        #(0x0005e1dc, b"1K0909144R \x003501", b"1K0909144R \x003502"),
        (0x0005e200, b"\x08\x00\x00\x00\x0E\x00\x37\x00\x6D\x00\xB1\x00\x11\x01\x43\x01\x50\x01\x00\x00\x16\x00\x30\x01\xD6\x02\xF4\x05\x69\x0C\xD2\x10\x00\x12\x00\x00",\
                     b"\x08\x00\x00\x00\x07\x00\x1F\x00\xC3\x00\xD8\x00\xF2\x00\x0D\x01\x21\x01\x00\x00\x58\x00\xE4\x01\x00\x0E\x77\x0F\xAB\x10\x5E\x11\x7C\x11\x00\x00"),
        (0x0005e224, b"\x08\x00\x00\x00\x0E\x00\x37\x00\x6D\x00\xB1\x00\x11\x01\x43\x01\x6C\x01\x00\x00\x12\x00\xF3\x00\x45\x02\xC3\x04\xEE\x09\x75\x0D\x00\x12\x00\x00",\
                     b"\x08\x00\x00\x00\x0D\x00\x4D\x00\x88\x00\xBE\x00\x10\x01\x59\x01\xA1\x01\x00\x00\x7D\x00\x33\x03\xB3\x05\x00\x08\xBC\x0B\xA2\x0F\x00\x14\x00\x00"),

        #(0x0005e248, b"1K0909144R \x003501", b"1K0909144R \x003502"),
        (0x0005e26c, b"\x08\x00\x00\x00\x0E\x00\x37\x00\x6D\x00\xB1\x00\x11\x01\x98\x01\x9F\x01\x00\x00\x0F\x00\xE7\x00\x24\x02\x44\x04\x19\x09\x70\x11\x00\x12\x00\x00",\
                     b"\x08\x00\x00\x00\x07\x00\x1F\x00\x3E\x00\x65\x00\x9B\x00\xE9\x00\x33\x01\x00\x00\x14\x00\xAB\x00\xA4\x01\x5C\x03\x00\x07\x1C\x0D\x9A\x11\x00\x00"),
        (0x0005e290, b"\x08\x00\x00\x00\x0E\x00\x37\x00\x6D\x00\xB1\x00\x11\x01\x98\x01\xBE\x01\x00\x00\x0C\x00\xB9\x00\xB6\x01\x6A\x03\x47\x07\xF3\x0D\x00\x12\x00\x00",\
                     b"\x08\x00\x00\x00\x0E\x00\x4D\x00\x88\x00\xBE\x00\x10\x01\x98\x01\x1C\x02\x00\x00\x31\x00\x0B\x01\x1F\x02\x4C\x03\xA0\x05\x33\x0B\x62\x12\x00\x00"),

        #(0x0005e2b4, b"1K0909144R \x003501", b"1K0909144R \x003502"),
        (0x0005e2d8, b"\x08\x00\x00\x00\x0E\x00\x37\x00\x6D\x00\xB1\x00\x11\x01\x98\x01\xEF\x01\x00\x00\x07\x00\x9A\x00\x76\x01\xD3\x02\xF6\x05\xA4\x0C\x00\x12\x00\x00",\
                     b"\x08\x00\x00\x00\x07\x00\x1F\x00\x3E\x00\x65\x00\x9B\x00\xE9\x00\x37\x01\x00\x00\x08\x00\x62\x00\x22\x01\x7C\x02\x3A\x05\xE6\x0A\x99\x11\x00\x00"),
        (0x0005e2fc, b"\x08\x00\x00\x00\x0E\x00\x37\x00\x6D\x00\xB1\x00\x11\x01\x98\x01\xFE\x01\x00\x00\x06\x00\x7B\x00\x2B\x01\x42\x02\xC5\x04\x1D\x0A\x00\x12\x00\x00",\
                     b"\x08\x00\x00\x00\x0E\x00\x4D\x00\x89\x00\xBE\x00\x10\x01\x97\x01\x20\x02\x00\x00\x0E\x00\x65\x00\xEA\x00\x97\x01\x54\x03\x41\x07\x2F\x0F\x00\x00"),

        #(0x0005e320, b"1K0909144R \x003501", b"1K0909144R \x003502"),
        (0x0005e344, b"\x08\x00\x00\x00\x0E\x00\x37\x00\x6D\x00\xB1\x00\x11\x01\x98\x01\x20\x02\x00\x00\x03\x00\x5C\x00\xF1\x00\xC6\x01\x9F\x03\x38\x08\xD7\x0E\x00\x00",\
                     b"\x08\x00\x00\x00\x07\x00\x1F\x00\x3E\x00\x65\x00\x9C\x00\xE9\x00\x37\x01\x00\x00\x03\x00\x3D\x00\xC1\x00\xB8\x01\xE0\x03\x27\x08\x9E\x0E\x00\x00"),
        (0x0005e368, b"\x08\x00\x00\x00\x0E\x00\x37\x00\x6D\x00\xB1\x00\x11\x01\x98\x01\x20\x02\x00\x00\x02\x00\x4A\x00\xC1\x00\x6B\x01\xE6\x02\x93\x06\xD7\x0E\x00\x00",\
                     b"\x08\x00\x00\x00\x0E\x00\x4D\x00\x88\x00\xBF\x00\x10\x01\x98\x01\x20\x02\x00\x00\x05\x00\x3E\x00\x78\x00\xE2\x00\xEC\x01\xA8\x04\x71\x0D\x00\x00"),

        #(0x0005e38c, b"1K0909144R \x003501", b"1K0909144R \x003502"),
        (0x0005e3b0, b"\x08\x00\x00\x00\x0E\x00\x37\x00\x6D\x00\xB1\x00\x11\x01\x98\x01\x20\x02\x00\x00\x01\x00\x25\x00\x5C\x00\xDD\x00\x33\x02\x69\x05\x8A\x0A\x00\x00",\
                     b"\x08\x00\x00\x00\x07\x00\x1F\x00\x3E\x00\x65\x00\x9C\x00\xE9\x00\x37\x01\x00\x00\x02\x00\x1B\x00\x6E\x00\x15\x01\x90\x02\xAA\x05\xD1\x0A\x00\x00"),
        (0x0005e3d4, b"\x08\x00\x00\x00\x0E\x00\x37\x00\x6D\x00\xB1\x00\x11\x01\x98\x01\x20\x02\x00\x00\x01\x00\x1E\x00\x4A\x00\xB1\x00\xC2\x01\x54\x04\x8A\x0A\x00\x00",\
                     b"\x08\x00\x00\x00\x0E\x00\x4D\x00\x88\x00\xBE\x00\x10\x01\x98\x01\x20\x02\x00\x00\x06\x00\x21\x00\x39\x00\x58\x00\xBC\x00\x15\x02\xD1\x0B\x00\x00"),

        #(0x0005e3f8, b"1K0909144R \x003501", b"1K0909144R \x003502"),
        (0x0005e41c, b"\x08\x00\x00\x00\x0D\x00\x36\x00\x6D\x00\xB1\x00\x10\x01\x98\x01\x20\x02\x00\x00\x08\x00\x62\x00\x22\x01\x7B\x02\x29\x05\xE4\x0A\x9A\x11\x00\x00",\
                     b"\x08\x00\x00\x00\x0D\x00\x36\x00\x6D\x00\xB1\x00\x10\x01\x98\x01\x20\x02\x00\x00\x08\x00\x62\x00\x22\x01\x7B\x02\x29\x05\xE4\x0A\x9A\x11\x00\x00"),
        (0x0005e440, b"\x08\x00\x00\x00\x0D\x00\x36\x00\x6D\x00\xB1\x00\x10\x01\x98\x01\x20\x02\x00\x00\x08\x00\x62\x00\x22\x01\x7B\x02\x29\x05\xE4\x0A\x9A\x11\x00\x00",\
                     b"\x08\x00\x00\x00\x0D\x00\x36\x00\x6D\x00\xB1\x00\x10\x01\x98\x01\x20\x02\x00\x00\x08\x00\x62\x00\x22\x01\x7B\x02\x29\x05\xE4\x0A\x9A\x11\x00\x00"),

        (0x0005FFFC, b"Ende", b"\xff\xff\xff\xff"),  # End of FW marker
    ]
}

# (checksum addr, start, end)
checksums = {
    "2501": [
        (0x05EFFC, 0x5E000, 0x5EFFC),
    ],
    "3501": [
        #ASW: A000 - 5C000
        (0x05fef8, 0x0a000, 0x0afff),
        (0x05fefa, 0x0afff, 0x0bffe),
        (0x05fefc, 0x0bffe, 0x0cffd),
        (0x05fefe, 0x0cffd, 0x0dffc),
        (0x05ff00, 0x0dffc, 0x0effb),
        (0x05ff02, 0x0effb, 0x0fffa),
        (0x05ff04, 0x0fffa, 0x10ff9),
        (0x05ff06, 0x10ff9, 0x11ff8),
        (0x05ff08, 0x11ff8, 0x12ff7),
        (0x05ff0a, 0x12ff7, 0x13ff6),
        (0x05ff0c, 0x13ff6, 0x14ff5),
        (0x05ff0e, 0x14ff5, 0x15ff4),
        (0x05ff10, 0x15ff4, 0x16ff3),
        (0x05ff12, 0x16ff3, 0x17ff2),
        (0x05ff14, 0x17ff2, 0x18ff1),
        (0x05ff16, 0x18ff1, 0x19ff0),
        (0x05ff18, 0x19ff0, 0x1afef),
        (0x05ff1a, 0x1afef, 0x1bfee),
        (0x05ff1c, 0x1bfee, 0x1cfed),
        (0x05ff1e, 0x1cfed, 0x1dfec),
        (0x05ff20, 0x1dfec, 0x1efeb),
        (0x05ff22, 0x1efeb, 0x1ffea),
        (0x05ff24, 0x1ffea, 0x20fe9),
        (0x05ff26, 0x20fe9, 0x21fe8),
        (0x05ff28, 0x21fe8, 0x22fe7),
        (0x05ff2a, 0x22fe7, 0x23fe6),
        (0x05ff2c, 0x23fe6, 0x24fe5),
        (0x05ff2e, 0x24fe5, 0x25fe4),
        (0x05ff30, 0x25fe4, 0x26fe3),
        (0x05ff32, 0x26fe3, 0x27fe2),
        (0x05ff34, 0x27fe2, 0x28fe1),
        (0x05ff36, 0x28fe1, 0x29fe0),
        (0x05ff38, 0x29fe0, 0x2afdf),
        (0x05ff3a, 0x2afdf, 0x2bfde),
        (0x05ff3c, 0x2bfde, 0x2cfdd),
        (0x05ff3e, 0x2cfdd, 0x2dfdc),
        (0x05ff40, 0x2dfdc, 0x2efdb),
        (0x05ff42, 0x2efdb, 0x2ffda),
        (0x05ff44, 0x2ffda, 0x30fd9),
        (0x05ff46, 0x30fd9, 0x31fd8),
        (0x05ff48, 0x31fd8, 0x32fd7),
        (0x05ff4a, 0x32fd7, 0x33fd6),
        (0x05ff4c, 0x33fd6, 0x34fd5),
        (0x05ff4e, 0x34fd5, 0x35fd4),
        (0x05ff50, 0x35fd4, 0x36fd3),
        (0x05ff52, 0x36fd3, 0x37fd2),
        (0x05ff54, 0x37fd2, 0x38fd1),
        (0x05ff56, 0x38fd1, 0x39fd0),
        (0x05ff58, 0x39fd0, 0x3afcf),
        (0x05ff5a, 0x3afcf, 0x3bfce),
        (0x05ff5c, 0x3bfce, 0x3cfcd),
        (0x05ff5e, 0x3cfcd, 0x3dfcc),
        (0x05ff60, 0x3dfcc, 0x3efcb),
        (0x05ff62, 0x3efcb, 0x3ffca),
        (0x05ff64, 0x3ffca, 0x40fc9),
        (0x05ff66, 0x40fc9, 0x41fc8),
        (0x05ff68, 0x41fc8, 0x42fc7),
        (0x05ff6a, 0x42fc7, 0x43fc6),
        (0x05ff6c, 0x43fc6, 0x44fc5),
        (0x05ff6e, 0x44fc5, 0x45fc4),
        (0x05ff70, 0x45fc4, 0x46fc3),
        (0x05ff72, 0x46fc3, 0x47fc2),
        (0x05ff74, 0x47fc2, 0x48fc1),
        (0x05ff76, 0x48fc1, 0x49fc0),
        (0x05ff78, 0x49fc0, 0x4afbf),
        (0x05ff7a, 0x4afbf, 0x4bfbe),
        (0x05ff7c, 0x4bfbe, 0x4cfbd),
        (0x05ff7e, 0x4cfbd, 0x4dfbc),
        (0x05ff80, 0x4dfbc, 0x4efbb),
        (0x05ff82, 0x4efbb, 0x4ffba),
        (0x05ff84, 0x4ffba, 0x50fb9),
        (0x05ff86, 0x50fb9, 0x51fb8),
        (0x05ff88, 0x51fb8, 0x52fb7),
        (0x05ff8a, 0x52fb7, 0x53fb6),
        (0x05ff8c, 0x53fb6, 0x54fb5),
        (0x05ff8e, 0x54fb5, 0x55fb4),
        (0x05ff90, 0x55fb4, 0x56fb3),
        (0x05ff92, 0x56fb3, 0x57fb2),
        (0x05ff94, 0x57fb2, 0x58fb1),
        (0x05ff96, 0x58fb1, 0x59fb0),
        (0x05ff98, 0x59fb0, 0x5afaf),
        (0x05ff9a, 0x5afaf, 0x5bfae),
        (0x05ff9c, 0x5bfae, 0x5c000),
        #Calibration: 5C000 - 5EFFE
        (0x05DFFC, 0x5C000, 0x5CFFF),
        (0x05DFFE, 0x5CFFF, 0x5DFFC),
        (0x05EFFE, 0x5E000, 0x5EFFE),
    ]
}
# fmt: on


def crc16(dat):
    xmodem_crc_func = crcmod.mkCrcFun(0x11021, rev=False, initCrc=0x0000, xorOut=0x0000)
    crc = xmodem_crc_func(dat)
    return struct.pack(">H", crc)


def verify_checksums(fw_in, config):
    for expected, start, end in config:
        if fw_in[expected : expected + 2] != crc16(fw_in[start:end]):
            return False

    return True


def update_checksums(fw_in, config):
    fw_out = fw_in
    for expected, start, end in config:
        fw_out = fw_out[:expected] + crc16(fw_in[start:end]) + fw_out[expected + 2 :]
    return fw_out


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("--input", required=True, help="input file to patch")
    parser.add_argument("--output", required=True, help="output file")
    parser.add_argument("--version", default="2501", const="2501", nargs="?", choices=["2501", "3501"])
    args = parser.parse_args()

    with open(args.input, "rb") as input_fw:
        input_fw_s = input_fw.read()

    output_fw_s = input_fw_s

    assert verify_checksums(output_fw_s, checksums[args.version])

    for addr, orig, new in patches[args.version]:
        length = len(orig)
        cur = input_fw_s[addr : addr + length]

        assert cur == orig, f"Unexpected values in input FW {cur.hex()} expected {orig.hex()}"

        if new is not None:
            assert len(new) == length
            output_fw_s = output_fw_s[:addr] + new + output_fw_s[addr + length :]
            assert output_fw_s[addr : addr + length] == new

    output_fw_s = update_checksums(output_fw_s, checksums[args.version])

    assert verify_checksums(output_fw_s, checksums[args.version])
    assert len(output_fw_s) == len(input_fw_s)

    with open(args.output, "wb") as output_fw:
        output_fw.write(output_fw_s)
