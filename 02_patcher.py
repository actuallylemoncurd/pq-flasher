#!/usr/bin/env python3
import struct
from argparse import ArgumentParser
import crcmod

# fmt: off
Override = b"\x99"
Override2 = b"\x99\x99"
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
        (0x0005E669, Override, b"\x76"),  #hca_lm_offset_torque_handler
        (0x0005E66A, Override, b"\x9C"),
        #(0x0005E66B, b"\x9B", b"\xFF"),
        (0x0005E671, Override, b"\x76"),
        (0x0005E672, Override, b"\x9C"),
        #(0x0005E673, b"\x9B", b"\xFF"),
        (0x0005E679, Override, b"\x76"),
        (0x0005E67A, Override, b"\x9C"),
        #(0x0005E67B, b"\x9B", b"\xFF"),
        # FUN_00029272 maps
        (0x0005E4A8, Override, b"\xC0"),  # 0005e0a8 map
        (0x0005E4AA, Override, b"\xC0"),
        (0x0005E4AC, Override2, b"\x85\x04"),
        (0x0005E4AE, Override2, b"\x85\x04"),
        (0x0005E4B0, Override2, b"\x19\x05"),
        (0x0005E4B2, Override2, b"\x19\x05"),
        (0x0005E4B4, Override2, b"\x78\x05"),
        (0x0005E4B6, Override2, b"\x78\x05"),
        #(0x0005E4B8, b"\x78\x05", b"\xF0\x0A"),
        (0x0005E4D4, Override, b"\xC0"),
        (0x0005E4D6, Override, b"\xC0"),
        (0x0005E4D8, Override2, b"\x85\x04"),
        (0x0005E4DA, Override2, b"\x85\x04"),
        (0x0005E4DC, Override2, b"\x19\x05"),
        (0x0005E4DE, Override2, b"\x19\x05"),
        (0x0005E4E0, Override2, b"\x78\x05"),
        (0x0005E4E2, Override2, b"\x78\x05"),
        #(0x0005E4E4, b"\x78\x05", b"\xF0\x0A"),
        (0x0005E500, Override, b"\xC0"),
        (0x0005E502, Override, b"\xC0"),
        (0x0005E504, Override2, b"\x85\x04"),
        (0x0005E506, Override2, b"\x85\x04"),
        (0x0005E508, Override2, b"\x19\x05"),
        (0x0005E50A, Override2, b"\x19\x05"),
        (0x0005E50C, Override2, b"\x78\x05"),
        (0x0005E50E, Override2, b"\x78\x05"),
        #(0x0005E510, b"\x78\x05", b"\xF0\x0A"),

        #(0x0005E52E, b"\x80\x00", b"\x00\x01"),  # 0005e0cc map
        (0x0005E530, Override2, b"\x80\x00"),
        (0x0005E532, Override2, b"\x80\x00"),
        (0x0005E534, Override2, b"\x78\x00"),
        (0x0005E536, Override2, b"\x78\x00"),
        (0x0005E538, Override2, b"\x57\x00"),
        #(0x0005E54A, b"\x80\x00", b"\x00\x01"),
        (0x0005E54C, Override2, b"\x80\x00"),
        (0x0005E54E, Override2, b"\x80\x00"),
        (0x0005E550, Override2, b"\x78\x00"),
        (0x0005E552, Override2, b"\x78\x00"),
        (0x0005E554, Override2, b"\x57\x00"),
        #(0x0005E566, b"\x80\x00", b"\x00\x01"),
        (0x0005E568, Override2, b"\x80\x00"),
        (0x0005E56A, Override2, b"\x80\x00"),
        (0x0005E56C, Override2, b"\x78\x00"),
        (0x0005E56E, Override2, b"\x78\x00"),
        (0x0005E570, Override2, b"\x57\x00"),

        #(0x0005E582, b"\x00\x04", b"\x00\x08"),  # 0005e0d8 map
        (0x0005E584, Override2, b"\x00\x04"),
        (0x0005E586, Override2, b"\x00\x04"),
        (0x0005E588, Override2, b"\xCD\x03"),
        (0x0005E58A, Override2, b"\xCD\x03"),
        (0x0005E58C, Override2, b"\x14\x03"),
        #(0x0005E59E, b"\x00\x04", b"\x00\x08"),
        (0x0005E5A0, Override2, b"\x00\x04"),
        (0x0005E5A2, Override2, b"\x00\x04"),
        (0x0005E5A4, Override2, b"\xCD\x03"),
        (0x0005E5A6, Override2, b"\xCD\x03"),
        (0x0005E5A8, Override2, b"\x14\x03"),
        #(0x0005E5BA, b"\x00\x04", b"\x00\x08"),
        (0x0005E5BC, Override2, b"\x00\x04"),
        (0x0005E5BE, Override2, b"\x00\x04"),
        (0x0005E5C0, Override2, b"\xCD\x03"),
        (0x0005E5C2, Override2, b"\xCD\x03"),
        (0x0005E5C4, Override2, b"\x14\x03"),

        (0x0005E5DC, Override, b"\x75"),  # 0005e0fc map
        (0x0005E5DD, Override, b"\x7F"),
        (0x0005E5DE, Override, b"\x7F"),
        (0x0005E5DF, Override, b"\x93"),
        (0x0005E5E0, Override, b"\x93"),
        #(0x0005E5E1, b"\x93\x00", b"\x26\x01"),
        (0x0005E5EC, Override, b"\x75"),
        (0x0005E5ED, Override, b"\x7F"),
        (0x0005E5EE, Override, b"\x7F"),
        (0x0005E5EF, Override, b"\x93"),
        (0x0005E5F0, Override, b"\x93"),
        #(0x0005E5F1, b"\x93\x00", b"\x26\x01"),
        (0x0005E5FC, Override, b"\x75"),
        (0x0005E5FD, Override, b"\x7F"),
        (0x0005E5FE, Override, b"\x7F"),
        (0x0005E5FF, Override, b"\x93"),
        (0x0005E600, Override, b"\x93"),
        #(0x0005E601, b"\x93\x00", b"\x26\x01"),

        #(0x0005E5C8, b"\x14", b"\x28"),  # 0005e0e4 map
        #(0x0005E5CA, b"\x14", b"\x28"),
        #(0x0005E5CC, b"\x14", b"\x28"),

        #(0x0005E518, b"\x0a", b"\x14"),  # 0005e0c0 map
        #(0x0005E51A, b"\x0a", b"\x14"),
        #(0x0005E51C, b"\x0a", b"\x14"),

        #(0x0005E5CE, b"\x42", b"\x84"),  # 0005e0f0 map
        #(0x0005E5D0, b"\x42", b"\x84"),
        #(0x0005E5D2, b"\x42", b"\x84"),
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

        if (cur != orig) and (orig != Override) or (orig != Override2):
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
