#!/usr/bin/env python3
import struct
from argparse import ArgumentParser
import crcmod

# fmt: off
Override = b"\x99"
# (addr, orig, new (optional) )
patches = {
    "2501": [
        (0x0005E7A8, b"1K0909144E \x002501", None),  # Software number and version
        (0x0005E221, b"\x64", b"\x00"),  # Disengage countdown
        (0x0005E283, b"\x32", b"\x00"),  # Min speed
        (0x0005FFFC, b"Ende", b"\xff\xff\xff\xff"),  # End of FW marker
    ],
    "3501": [
        (0x0005D828, b"1K0909144R \x003501", None),  # Software number and version
        (0x0005D289, b"\x64", b"\x00"),  # Disengage countdown
        (0x0005D2FA, b"\x14", b"\x00"),  # Min speed
        (0x0005FFFC, b"Ende", b"\xff\xff\xff\xff"),  # End of FW marker
    ],
    "3501Torque": [
        # willem baseline
        (0x0005D828, b"1K0909144R \x003501", None),  # Software number and version
        (0x0005D289, b"\x64", b"\x00"),  # Disengage countdown
        (0x0005D2FA, b"\x14", b"\x00"),  # Min speed
        (0x0005FFFC, b"Ende", b"\xff\xff\xff\xff"),  # End of FW marker
        # many_hca_checks violation flag value buff
        (0x0005D0A8, Override, b"\x98"),
        (0x0005D0A9, Override, b"\x01"),
        (0x0005D0AA, Override, b"\x98"),
        (0x0005D0AB, Override, b"\x01"),
        # Loosen clamp
        (0x0005D044, Override, b"\x8b"),  #change boost from 0x440 to 0x38b.
        (0x0005D045, Override, b"\x03"),  #0x38b is found STOCK in kamolds fw, 0x220 is found elsewhere. so we know its a good value, and should indeed be higher than needed for 5, even 6nm
        
        # Booooooooooooost
        (0x0005E667, b"\x32", b"\x64"),  #hca_lm_offset_torque_handler
        (0x0005E66F, b"\x32", b"\x64"),
        (0x0005E677, b"\x32", b"\x64"),
        # FUN_00029272 maps
        (0x0005E518, b"\x0a", b"\x14"),  # 0005e0c0 map
        (0x0005E51A, b"\x0a", b"\x14"),
        (0x0005E51C, b"\x0a", b"\x14"),

        (0x0005E494, b"\x0C", b"\x18"),  # 0005e0a8 map
        (0x0005E496, b"\x2E", b"\x5C"),
        (0x0005E494, b"\xE4", b"\xC8"),
        (0x0005E495, b"\x00", b"\x01"),
        (0x0005E49A, b"\xFF", b"\xFE"),
        (0x0005E49B, b"\x01", b"\x03"),
        (0x0005E4C0, b"\x0C", b"\x18"),
        (0x0005E4C2, b"\x2E", b"\x5C"),
        (0x0005E4C4, b"\xE4", b"\xC8"),
        (0x0005E4C5, b"\x00", b"\x01"),
        (0x0005E4C6, b"\xFF", b"\xFE"),
        (0x0005E4C7, b"\x01", b"\x03"),
        (0x0005E4EC, b"\x0C", b"\x18"),
        (0x0005E4EE, b"\x2E", b"\x5C"),
        (0x0005E4F0, b"\xE4", b"\xC8"),
        (0x0005E4F1, b"\x00", b"\x01"),
        (0x0005E4F2, b"\xFF", b"\xFE"),
        (0x0005E4F3, b"\x01", b"\x03"),

        (0x0005E524, b"\x0E", b"\x1C"),  # 0005e0cc map
        (0x0005E526, b"\x44", b"\x88"),

        (0x0005E578, b"\x0E", b"\x1C"),  # 0005e0d8 map
        (0x0005E57A, b"\x44", b"\x88"),
        (0x0005E594, b"\x0E", b"\x1C"),
        (0x0005E596, b"\x44", b"\x88"),
        (0x0005E5B0, b"\x0E", b"\x1C"),
        (0x0005E5B2, b"\x44", b"\x88"),

        (0x0005E5C8, b"\x14", b"\x28"),  # 0005e0e4 map
        (0x0005E5CA, b"\x14", b"\x28"),
        (0x0005E5CC, b"\x14", b"\x28"),

        (0x0005E5CE, b"\x42", b"\x84"),  # 0005e0f0 map
        (0x0005E5D0, b"\x42", b"\x84"),
        (0x0005E5D2, b"\x42", b"\x84"),

        (0x0005E5D7, b"\x0F", b"\x1E"),  # 0005e0fc map
        (0x0005E5D8, b"\x32", b"\x64"),
        (0x0005E5D9, b"\x64", b"\xC8"),
        (0x0005E5E7, b"\x0F", b"\x1E"),
        (0x0005E5E8, b"\x32", b"\x64"),
        (0x0005E5E9, b"\x64", b"\xC8"),
        (0x0005E5F7, b"\x0F", b"\x1E"),
        (0x0005E5F8, b"\x32", b"\x64"),
        (0x0005E5F9, b"\x64", b"\xC8"),
    ]
}

# (checksum addr, start, end)
checksums = {
    "2501": [
        (0x05EFFC, 0x5E000, 0x5EFFC),
    ],
    "3501": [
        (0x05DFFC, 0x5C000, 0x5CFFF),
        (0x05DFFE, 0x5CFFF, 0x5DFFC),
        (0x05EFFE, 0x5E000, 0x5EFFE),
    ],
    "3501Torque": [
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
    parser.add_argument("--version", default="2501", const="2501", nargs="?", choices=["2501", "3501", "3501Torque"])
    args = parser.parse_args()

    with open(args.input, "rb") as input_fw:
        input_fw_s = input_fw.read()

    output_fw_s = input_fw_s

    assert verify_checksums(output_fw_s, checksums[args.version])

    for addr, orig, new in patches[args.version]:
        length = len(orig)
        cur = input_fw_s[addr : addr + length]

        if (cur != orig) and orig != Override:
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
