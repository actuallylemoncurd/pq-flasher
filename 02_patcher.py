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

        # Loosen clamp
        #(0x0005D044, Override, b"\x40"),  # temporarily boost to 0x440 whilst testing for HCA maps
        #(0x0005D045, Override, b"\x04"),  # 0x38B is the highest observed clamp limit STOCK

        # hca_lm_offset map
        (0x0005E669, b"\x53\x76\x9C", b"\x53\xA0\xEA"),  # 0x5E150 map
        (0x0005E671, b"\x53\x76\x9C", b"\x53\xA0\xEA"),
        (0x0005E679, b"\x53\x76\x9C", b"\x53\xA0\xEA"),
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
