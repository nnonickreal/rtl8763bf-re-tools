#!/usr/bin/env python3
"""
dump_jbl510bt.py (v5) — Standalone Realtek RTL8763BF (BBPro / Cut 5) 1 MiB SPI Flash Dumper
Reverse-engineered directly from Realtek MPPGTool-v4.0.43.42 (MPPGTool.exe + RtkMPPGExport.dll
+ Image/firmware3.bin) and RTL8763B Series Datasheet (Rev 0.9) for JBL Tune 510BT (QFN40).
"""

import argparse
import base64
import hashlib
import os
import struct
import sys
import time
import zlib
from pathlib import Path

try:
    import serial
except ImportError:
    print("[-] pyserial is required: pip install pyserial", file=sys.stderr)
    sys.exit(1)


# Exact baudrate divisor words from RtkMPPGExport.dll @ 0x10063fd0 (HCI 0xFC17)
BAUD_DIVISORS = {
    115200:  0x0252C014,
    230400:  0x0252C00A,
    460800:  0x0252C005,
    921600:  0x05F75004,
    1000000: 0x00005004,
    1500000: 0x04928002,
    2000000: 0x00005002,
}

FLASH_BASE_DEFAULT = 0x00800000
FLASH_SIZE_DEFAULT = 0x00100000  # 1 MiB (RTL8763BF internal stacked SPI NOR)
ROM_BASE_DEFAULT = 0x00000000
ROM_SIZE_DEFAULT = 0x000C0000    # 768 KiB (RTL8763B BootROM + BT Stack / RTOS SysROM: 0x00000000..0x000BFFFF)

# BBPro 1 MiB flash layout from RtkMPPGExport.dll @ 0x1004da90..0x1004dc40
BBPRO_PARTITIONS = [
    (0x000000, 0x001000, "Flash Header / Reserved"),
    (0x001000, 0x001000, "OCCD / OEM Config (0x0100)"),
    (0x002000, 0x036000, "Boot Patch (0x0200)"),
    (0x038000, 0x020000, "System / Stack Patch (0x0300)"),
    (0x058000, 0x001000, "OTA Bank Header (0x0410)"),
    (0x059000, 0x083000, "MCU App Image (0x0400)"),
    (0x0DC000, 0x010000, "DSP System / Config (0x0500)"),
    (0x0EC000, 0x014000, "App Data / Voice Prompts (0x0602)"),
]

# RtkMPPGExport.dll @ 0x1007a7aa & 0x1007a986 (RTL8763BF Cut 5 BootROM unlock constants)
RTL8763BF_DEFAULT_EFUSE_KEY = bytes.fromhex("0650171b82a2161cf3d88a7448c52abb")
RTL8763BF_UNLOCK_CIPHERTEXT = bytes.fromhex("1d757dd932d769bbe7a76b59d5e49034")

# Exact Image/firmware3.bin (2,416 bytes, SHA-256: 708461fd16e622f3...) from MPPGTool-v4.0.43.42
# ("MP Loader: Sep 10 2018", loads at 0x10080c00, entry 0x10080c01).
EMBEDDED_FIRMWARE3_ZLIB_B64 = (
    "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"
)


# ----------------------------------------------------------------------
# Pure-Python FIPS-197 AES-128-ECB Decrypt (zero external dependencies)
# Matches RtkMPPGExport.dll CAes @ 0x10011430 / 0x10012fe0 / 0x10013160
# ----------------------------------------------------------------------
def _build_aes_tables() -> tuple[bytes, bytes]:
    sbox = bytearray(256)
    isbox = bytearray(256)

    def rotl8(x: int, shift: int) -> int:
        return ((x << shift) | (x >> (8 - shift))) & 0xFF

    p = 1
    q = 1
    while True:
        p = p ^ ((p << 1) & 0xFF) ^ (0x1B if (p & 0x80) else 0)
        q ^= (q << 1) & 0xFF
        q ^= (q << 2) & 0xFF
        q ^= (q << 4) & 0xFF
        q ^= 0x09 if (q & 0x80) else 0
        q &= 0xFF
        xf = q ^ rotl8(q, 1) ^ rotl8(q, 2) ^ rotl8(q, 3) ^ rotl8(q, 4) ^ 0x63
        sbox[p] = xf
        isbox[xf] = p
        if p == 1:
            break
    sbox[0] = 0x63
    isbox[0x63] = 0x00
    return bytes(sbox), bytes(isbox)


_AES_SBOX, _AES_ISBOX = _build_aes_tables()
_AES_RCON = (0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)


def _gf_mul(a: int, b: int) -> int:
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        a = (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else ((a << 1) & 0xFF)
        b >>= 1
    return p


def aes128_ecb_decrypt_block(ct: bytes, key: bytes) -> bytes:
    """Decrypt one 16-byte AES-128 block (matches RtkMPPGExport.dll @ 0x10013160 with zero IV)."""
    if len(ct) != 16 or len(key) != 16:
        raise ValueError("AES-128 block and key must each be 16 bytes")
    w = [list(key[i * 4 : (i + 1) * 4]) for i in range(4)]
    for i in range(4, 44):
        t = list(w[i - 1])
        if i % 4 == 0:
            t = [
                _AES_SBOX[t[1]] ^ _AES_RCON[i // 4],
                _AES_SBOX[t[2]],
                _AES_SBOX[t[3]],
                _AES_SBOX[t[0]],
            ]
        w.append([w[i - 4][j] ^ t[j] for j in range(4)])

    st = [list(ct[c * 4 : (c + 1) * 4]) for c in range(4)]

    def add_rk(rnd: int):
        for c in range(4):
            for r in range(4):
                st[c][r] ^= w[rnd * 4 + c][r]

    def inv_shift_rows():
        for r in (1, 2, 3):
            row = [st[c][r] for c in range(4)]
            for c in range(4):
                st[c][r] = row[(c - r) % 4]

    def inv_sub_bytes():
        for c in range(4):
            for r in range(4):
                st[c][r] = _AES_ISBOX[st[c][r]]

    def inv_mix_cols():
        for c in range(4):
            a0, a1, a2, a3 = st[c]
            st[c] = [
                _gf_mul(a0, 0x0E) ^ _gf_mul(a1, 0x0B) ^ _gf_mul(a2, 0x0D) ^ _gf_mul(a3, 0x09),
                _gf_mul(a0, 0x09) ^ _gf_mul(a1, 0x0E) ^ _gf_mul(a2, 0x0B) ^ _gf_mul(a3, 0x0D),
                _gf_mul(a0, 0x0D) ^ _gf_mul(a1, 0x09) ^ _gf_mul(a2, 0x0E) ^ _gf_mul(a3, 0x0B),
                _gf_mul(a0, 0x0B) ^ _gf_mul(a1, 0x0D) ^ _gf_mul(a2, 0x09) ^ _gf_mul(a3, 0x0E),
            ]

    add_rk(10)
    for rnd in range(9, 0, -1):
        inv_shift_rows()
        inv_sub_bytes()
        add_rk(rnd)
        inv_mix_cols()
    inv_shift_rows()
    inv_sub_bytes()
    add_rk(0)
    return bytes(st[c][r] for c in range(4) for r in range(4))


def compute_rtl8763bf_fd60_token(efuse_key: bytes, xtal_cfg: int) -> bytes:
    """
    Exact port of RtkMPPGExport.dll @ 0x1007a670..0x1007ab55:
      pt = AES128_Decrypt(key=efuse_key, ct=1d757dd932d769bbe7a76b59d5e49034)
      token = bytearray(pt); token[3] |= (xtal_cfg & 0xFF)
    For factory default key 0650171b... and XTAL=0x1B:
      pt    = 99 a5 77 00 6d b0 c1 27 1b a0 a6 eb aa 64 a8 99
      token = 99 a5 77 1b 6d b0 c1 27 1b a0 a6 eb aa 64 a8 99
    """
    pt = bytearray(aes128_ecb_decrypt_block(RTL8763BF_UNLOCK_CIPHERTEXT, efuse_key))
    pt[3] |= xtal_cfg & 0xFF
    return bytes(pt)


# Self-check AES-128 & default RTL8763BF token at import time
assert (
    compute_rtl8763bf_fd60_token(RTL8763BF_DEFAULT_EFUSE_KEY, 0x1B).hex()
    == "99a5771b6db0c1271ba0a6ebaa64a899"
)


def _make_crc16_arc_table() -> list[int]:
    """CRC-16/ARC (poly=0xA001 reflected, init=0x0000) — matches RtkMPPGExport.dll @ 0x10142b90."""
    tbl = []
    for i in range(256):
        crc = i
        for _ in range(8):
            crc = ((crc >> 1) ^ 0xA001) if (crc & 1) else (crc >> 1)
        tbl.append(crc & 0xFFFF)
    return tbl


CRC16_ARC_TABLE = _make_crc16_arc_table()


def crc16_arc(data: bytes, init: int = 0x0000) -> int:
    """Exact port of RtkMPPGExport.dll @ 0x1002c930."""
    crc = init & 0xFFFF
    tbl = CRC16_ARC_TABLE
    for b in data:
        crc = ((crc >> 8) ^ tbl[(crc ^ b) & 0xFF]) & 0xFFFF
    return crc


class Rtl8763Dumper:
    def __init__(self, port: str, init_baud: int = 115200, timeout: float = 1.5, verbose: bool = False, ser_obj=None):
        self.port_name = port
        self.verbose = verbose
        self.in_mp_loader = False
        if ser_obj is not None:
            self.ser = ser_obj
        else:
            self.ser = serial.Serial(
                port=port,
                baudrate=init_baud,
                bytesize=serial.EIGHTBITS,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE,
                timeout=timeout,
                xonxoff=False,
                rtscts=False,
                dsrdtr=False,
            )
        self.ser.reset_input_buffer()
        self.ser.reset_output_buffer()

    def close(self):
        if self.ser and self.ser.is_open:
            self.ser.close()

    def _read_exact(self, n: int, timeout: float = 2.0) -> bytes:
        buf = bytearray()
        deadline = time.monotonic() + timeout
        while len(buf) < n:
            if time.monotonic() > deadline:
                raise TimeoutError(f"UART timeout: got {len(buf)}/{n} bytes ({buf.hex()})")
            chunk = self.ser.read(n - len(buf))
            if chunk:
                buf.extend(chunk)
        return bytes(buf)

    # ------------------------------------------------------------------
    # Transport A: Standard Bluetooth H4 HCI (BootROM mode)
    # ------------------------------------------------------------------
    def hci_cmd(self, opcode: int, params: bytes = b"", timeout: float = 2.0) -> tuple[int, bytes]:
        """
        Send H4 HCI Command packet:
          TX: 01 <opcode_lo> <opcode_hi> <plen> <params...>
          RX: 04 0E <elen> <ncmd> <opcode_lo> <opcode_hi> <status> <ret_params...>
        Returns (status, ret_params).
        """
        if len(params) > 255:
            raise ValueError(f"HCI params too long: {len(params)}")
        pkt = struct.pack("<BHB", 0x01, opcode, len(params)) + params
        if self.verbose:
            print(f"  [HCI TX] {pkt.hex()}")
        self.ser.reset_input_buffer()
        self.ser.write(pkt)
        self.ser.flush()

        deadline = time.monotonic() + timeout
        while True:
            if time.monotonic() > deadline:
                raise TimeoutError(f"Timeout waiting for HCI Event (opcode 0x{opcode:04X})")
            b = self.ser.read(1)
            if not b:
                continue
            if b[0] != 0x04:
                if self.verbose:
                    print(f"  [HCI skip non-event byte 0x{b[0]:02X}]")
                continue

            hdr = self._read_exact(2, timeout=max(0.3, deadline - time.monotonic()))
            evt_code, plen = hdr[0], hdr[1]
            payload = self._read_exact(plen, timeout=max(0.5, deadline - time.monotonic()))
            if self.verbose:
                print(f"  [HCI RX] 04{hdr.hex()}{payload.hex()}")

            if evt_code == 0x0E and plen >= 4:  # HCI_Command_Complete
                _ncmd, rx_op, status = struct.unpack_from("<BHB", payload, 0)
                if rx_op == opcode:
                    return status, payload[4:]

    def read_local_version(self) -> dict:
        """HCI_Read_Local_Version_Information (0x1001)."""
        status, data = self.hci_cmd(0x1001, timeout=1.2)
        if status != 0x00 or len(data) < 8:
            raise RuntimeError(f"0x1001 failed: status=0x{status:02X}, data={data.hex()}")
        hci_ver, hci_rev, lmp_ver, manuf, lmp_subver = struct.unpack_from("<BHbHH", data, 0)
        return {
            "hci_ver": hci_ver,
            "hci_rev": hci_rev,
            "lmp_ver": lmp_ver,
            "manufacturer": manuf,
            "lmp_subver": lmp_subver,
        }

    def read_rom_version(self) -> int:
        """HCI_Vendor_Read_ROM_Version (0xFC6D) — RtkMPPGExport.dll @ 0x100619f2."""
        status, data = self.hci_cmd(0xFC6D, timeout=1.0)
        if status != 0x00 or len(data) < 1:
            raise RuntimeError(f"0xFC6D status=0x{status:02X}")
        return data[0]

    def read_mem32_fc29(self, addr: int) -> int:
        """
        HCI_Vendor_Read_Mem32 (0xFC29) — RtkMPPGExport.dll @ 0x10065f00.
        TX: 01 29 FC 04 <addr:u32>
        RX: 04 0E 08 xx 29 FC <status> <val:u32>
        """
        status, data = self.hci_cmd(0xFC29, struct.pack("<I", addr), timeout=1.5)
        if status != 0x00 or len(data) < 4:
            raise RuntimeError(f"0xFC29 @ 0x{addr:08X} failed: status=0x{status:02X}")
        return struct.unpack_from("<I", data, 0)[0]

    def read_xtal_cfg(self) -> int:
        """
        Exact port of RtkMPPGExport.dll @ 0x10061c53 (Cut 5):
        reads 0x1000508A & 0xFF via 0xFC29 (with aligned 0x10005088 >> 16 fallback).
        """
        try:
            return self.read_mem32_fc29(0x1000508A) & 0xFF
        except Exception:
            return (self.read_mem32_fc29(0x10005088) >> 16) & 0xFF

    def hci_send_noack(self, opcode: int, params: bytes = b""):
        """
        Exact port of RtkMPPGExport.dll @ 0x10064fd0 (SendHciCommandNoAck):
        Writes H4 HCI Command packet WITHOUT waiting for an 04 0E event!
        Used exclusively by 0x100648a0 for HCI 0xFD60 (RTL8763BF BootROM unlock),
        which re-clocks/unlocks BootROM silently over 3000 ms without emitting 04 0E.
        """
        if len(params) > 255:
            raise ValueError(f"HCI params too long: {len(params)}")
        pkt = struct.pack("<BHB", 0x01, opcode, len(params)) + params
        if self.verbose:
            print(f"  [HCI TX NoAck] {pkt.hex()}")
        self.ser.reset_input_buffer()
        self.ser.write(pkt)
        self.ser.flush()

    def unlock_rtl8763bf_bootrom(self, efuse_key: bytes, xtal_cfg: int, settle_sec: float = 3.1):
        """
        Exact port of RtkMPPGExport.dll @ 0x1007a670 -> 0x100648a0 -> 0x10064fd0 (HCI 0xFD60):
        1. Sends 01 60 FD 10 <16-byte AES token> via 0x10064fd0 (NO 04 0E event expected!).
        2. Sleeps 3000 ms (0x1007abee: push 0xbb8; call Sleep) while BootROM unlocks 0xFC62
           and powers up XTAL/SPIC/Flash.
        """
        token = compute_rtl8763bf_fd60_token(efuse_key, xtal_cfg)
        print(
            f"[*] Sending RTL8763BF BootROM AES-128 unlock (HCI 0xFD60 NoAck): {token.hex()} "
            f"(frame=0x{token[0]:02X}..0x{token[15]:02X}, XTAL=0x{xtal_cfg:02X})..."
        )
        self.hci_send_noack(0xFD60, token)
        print(f"[*] Waiting {settle_sec:.1f}s (RtkMPPGExport.dll Sleep(3000)) for BootROM unlock & Flash power-up...")
        time.sleep(settle_sec)
        if self.verbose:
            waiting = self.ser.in_waiting
            if waiting:
                rx_any = self.ser.read(waiting)
                print(f"  [HCI post-0xFD60 RX drain ({len(rx_any)} B)]: {rx_any.hex()}")
        self.ser.reset_input_buffer()
        # Confirm BootROM HCI is alive after the 3s re-init window
        _ = self.read_local_version()
        print("[+] BootROM unlocked and responsive after 0xFD60!")

    def switch_baudrate_hci(self, baud: int):
        """HCI_Vendor_Set_Baudrate (0xFC17) — RtkMPPGExport.dll @ 0x100649d0."""
        if baud not in BAUD_DIVISORS:
            raise ValueError(f"Unsupported baud {baud}; valid: {sorted(BAUD_DIVISORS)}")
        div = BAUD_DIVISORS[baud]
        status, _ = self.hci_cmd(0xFC17, struct.pack("<I", div), timeout=1.5)
        if status != 0x00:
            raise RuntimeError(f"0xFC17 baud switch failed: status=0x{status:02X}")
        time.sleep(0.06)
        self.ser.baudrate = baud
        time.sleep(0.06)
        self.ser.reset_input_buffer()

    def flash_read_fc2d(self, addr: int, length: int) -> bytes:
        """
        HCI_Vendor_Flash_Read (0xFC2D) — RtkMPPGExport.dll @ 0x10063d50 + 0x10063e70 (max 244 bytes).
        TX: 01 2D FC 08 <addr:u32> <len:u32>
        RX: 04 0E <plen=8+len> <ncmd> 2D FC <status> <ret_len:u32> <data[ret_len]>
        """
        if not (1 <= length <= 0xF4):
            raise ValueError("0xFC2D chunk length must be 1..244 (0xF4)")
        status, data = self.hci_cmd(0xFC2D, struct.pack("<II", addr, length), timeout=2.5)
        if status != 0x00:
            raise RuntimeError(f"0xFC2D @ 0x{addr:08X} failed with HCI status=0x{status:02X}")
        if len(data) == length + 4:
            ret_len = struct.unpack_from("<I", data, 0)[0]
            if ret_len != length:
                raise RuntimeError(f"0xFC2D ret_len mismatch @ 0x{addr:08X}: {ret_len} != {length}")
            return data[4 : 4 + length]
        if len(data) == length:
            return data
        raise RuntimeError(f"0xFC2D unexpected rx len @ 0x{addr:08X}: got {len(data)} B (expected {length + 4})")

    def upload_and_start_mp_loader(self, fw_bytes: bytes, boot_wait_sec: float = 1.05):
        """
        Exact port of RtkMPPGExport.dll @ 0x100631e0 + 0x10063420 (Cut 5 / RTL8763BF):
          1. Upload Image/firmware3.bin in 252-byte (0xFC) chunks via HCI 0xFC20 with
             plain index 0..9 (NO 0x80 bit on the last chunk!).
          2. Send HCI 0xFC62: 20 8C 22 00 10 01 0C 08 10 ([0x1000228c] = 0x10080c01).
             Note: RtkMPPGExport.dll @ 0x10063711..0x100638c0 accepts BOTH status=0x00
             (followed by Sleep(1000)) AND timeout (-2) as success!
        """
        chunk_max = 0xFC  # 252 bytes
        total_chunks = (len(fw_bytes) + chunk_max - 1) // chunk_max
        for idx in range(total_chunks):
            part = fw_bytes[idx * chunk_max : (idx + 1) * chunk_max]
            params = bytes([idx & 0x7F]) + part
            status, _ = self.hci_cmd(0xFC20, params, timeout=2.0)
            if status != 0x00:
                raise RuntimeError(f"0xFC20 chunk {idx}/{total_chunks} failed: status=0x{status:02X}")

        hook_params = struct.pack("<BII", 0x20, 0x1000228C, 0x10080C01)
        try:
            status, _ = self.hci_cmd(0xFC62, hook_params, timeout=1.0)
            if status != 0x00:
                raise RuntimeError(f"0xFC62 rejected: status=0x{status:02X}")
            # RtkMPPGExport.dll @ 0x100638b5: Sleep(1000) while firmware3.bin runs flash_nor_init!
            time.sleep(boot_wait_sec)
        except TimeoutError:
            # RtkMPPGExport.dll @ 0x10063711: -2 (1000 ms timeout) means CPU jumped directly to 0x10080c01
            time.sleep(0.2)

        self.ser.reset_input_buffer()
        self.in_mp_loader = True

    # ------------------------------------------------------------------
    # Transport B: Realtek MP Loader 0x87 binary protocol (firmware3.bin)
    # ------------------------------------------------------------------
    def mp_cmd(self, cmd_id: int, payload: bytes = b"", timeout: float = 3.0) -> bytes:
        """
        Exact port of RtkMPPGExport.dll @ 0x10032100 / 0x10032230 / 0x100323e0:
          TX: [0x87] [cmd:u16_le] [payload:N] [crc16_arc:u16_le]
          RX: [0x87] [cmd:u16_le] [status:u8] [len:u32_le] [data:len] [crc16_arc:u16_le]
        """
        body = struct.pack("<BH", 0x87, cmd_id) + payload
        tx_crc = crc16_arc(body)
        pkt = body + struct.pack("<H", tx_crc)
        if self.verbose:
            print(f"  [MP TX] cmd=0x{cmd_id:04X} ({len(pkt)} B): {pkt.hex()}")

        self.ser.reset_input_buffer()
        self.ser.write(pkt)
        self.ser.flush()

        deadline = time.monotonic() + timeout
        while True:
            if time.monotonic() > deadline:
                raise TimeoutError(f"MP Loader timeout waiting for 0x87 sync (cmd 0x{cmd_id:04X})")
            b = self.ser.read(1)
            if not b:
                continue
            if b[0] == 0x87:
                break
            if self.verbose:
                print(f"  [MP skip byte 0x{b[0]:02X}]")

        hdr_rest = self._read_exact(7, timeout=max(0.5, deadline - time.monotonic()))
        rx_cmd, status, data_len = struct.unpack_from("<HBI", hdr_rest, 0)
        if rx_cmd != cmd_id:
            raise RuntimeError(f"MP Loader cmd mismatch: got 0x{rx_cmd:04X}, expected 0x{cmd_id:04X}")
        if status != 0x00:
            raise RuntimeError(f"MP Loader cmd 0x{cmd_id:04X} returned error status=0x{status:02X}")
        if data_len > 0x20000:
            raise RuntimeError(f"MP Loader implausible length {data_len} on cmd 0x{cmd_id:04X}")

        tail = self._read_exact(data_len + 2, timeout=max(1.0, deadline - time.monotonic()))
        data = tail[:data_len]
        rx_crc = struct.unpack_from("<H", tail, data_len)[0]
        calc_crc = crc16_arc(b"\x87" + hdr_rest + data)
        if rx_crc != calc_crc:
            raise RuntimeError(
                f"MP Loader CRC16 mismatch on cmd 0x{cmd_id:04X}: "
                f"rx=0x{rx_crc:04X} != calc=0x{calc_crc:04X}"
            )
        return data

    def mp_flash_read(self, addr: int, length: int) -> bytes:
        """MP Loader Flash Read (cmd 0x1033) — RtkMPPGExport.dll @ 0x10030d90."""
        data = self.mp_cmd(0x1033, struct.pack("<II", addr, length), timeout=3.5)
        if len(data) != length:
            raise RuntimeError(f"MP Loader 0x1033 length mismatch: got {len(data)}, expected {length}")
        return data

    def mp_switch_baudrate(self, baud: int):
        """
        MP Loader Baudrate Update (cmd 0x1010) — RtkMPPGExport.dll @ 0x100312b0 + 0x1007a595.
        Note: firmware3.bin @ 0x10080f20..0x10080f5e supports 115200, 230400, 460800, 500000,
        921600, 1000000, 2000000, 3000000 (NOT 1500000 — RtkMPPGExport.dll uses 1000000 = 0xF4240).
        """
        if baud == 1500000:
            print("[*] Note: MP Loader (firmware3.bin) uses 1000000 instead of 1500000; switching to 1000000 baud...")
            baud = 1000000
        self.mp_cmd(0x1010, struct.pack("<IB", baud, 0xFF), timeout=1.5)
        # RtkMPPGExport.dll @ 0x1007a595: Sleep(1000) before host SetCommState
        time.sleep(1.0)
        self.ser.baudrate = baud
        time.sleep(0.1)
        self.ser.reset_input_buffer()


def load_firmware3_bytes(explicit_path: str | None) -> tuple[bytes, str]:
    """Load Image/firmware3.bin from disk if present, otherwise use exact embedded copy."""
    script_dir = Path(__file__).resolve().parent
    candidates = []
    if explicit_path:
        candidates.append(Path(explicit_path))
    candidates.extend([
        script_dir / "Image" / "firmware3.bin",
        script_dir / "firmware3.bin",
        script_dir / "mppgtool" / "Image" / "firmware3.bin",
        Path.cwd() / "Image" / "firmware3.bin",
        Path.cwd() / "firmware3.bin",
    ])
    for p in candidates:
        if p.is_file():
            raw = p.read_bytes()
            if len(raw) == 2416:
                return raw, str(p)
    raw = zlib.decompress(base64.b64decode(EMBEDDED_FIRMWARE3_ZLIB_B64))
    return raw, "embedded Image/firmware3.bin (2,416 B)"


# 98-byte Thumb-2 hook appended at 0x10081570 (+0x970 in firmware3.bin; total 2,514 B = same 10x 252B 0xFC20 chunks):
#   - If (addr >> 22) == 2 (0x00800000..0x00BFFFFF SPI NOR): branches to original dfu_mp_read_flash (0x10080d7e).
#   - Otherwise (0x00000000..0x000BFFFF BootROM/SysROM, 0x00200000/0x10000000 RAM, 0x40000000 MMIO):
#     copies `len` bytes directly from CPU address space into aligned staging buffer (r0+0x100 inside the
#     80 KiB MP heap @ 0x10008400) and sends [0x87][0x1033][0x00][len:4][data][crc16:2] via mp_send_pkt (0x10080cc0).
RAW_CPU_READ_CALLSITE_5C6 = bytes.fromhex("00f0d3f9")  # bl #0x10081570 @ 0x100811c6
RAW_CPU_READ_HOOK_970 = bytes.fromhex(
    "8278c37842ea0322037942ea0342437942ea0362"  # r2 = u32_le(r0 + 2) [addr]
    "930d022b01d1fff7f8bb"                      # if (addr >> 22) == 2: b.w 0x10080d7e (dfu_mp_read_flash)
    "f0b517460478437844ea0324"                  # push {r4-r7,lr}; r7 = addr; r4 = u16_le(r0 + 0) [opcode]
    "8579c37945ea0325037a45ea0345437a45ea0365"  # r5 = u32_le(r0 + 6) [len]
    "00f5807626f00306"                          # r6 = (r0 + 0x100) & ~3 [staging buf in 0x10008400 heap]
    "0023ab4203d2fa5cf2545b1cf9e7"              # for (r3=0; r3<r5; r3++) r6[r3] = ((uint8_t*)r7)[r3]
    "204600212a463346fff778fbf0bd"              # mp_send_pkt(r4, 0, r5, r6); pop {r4-r7,pc}
)


def patch_firmware3_raw_cpu_read(fw_bytes: bytes) -> bytes:
    """Extend Image/firmware3.bin (2,416 -> 2,514 B) so cmd 0x1033 reads ROM/RAM directly from CPU bus."""
    if len(fw_bytes) != 2416 or fw_bytes[0x5C6:0x5CA] != bytes.fromhex("fff7dafd"):
        raise ValueError("Unexpected firmware3.bin layout for raw CPU read hook")
    patched = bytearray(fw_bytes)
    patched[0x5C6:0x5CA] = RAW_CPU_READ_CALLSITE_5C6
    patched.extend(RAW_CPU_READ_HOOK_970)
    return bytes(patched)


def is_spi_flash_region(addr: int, size: int) -> bool:
    return 0x00800000 <= addr and (addr + size) <= 0x00C00000


def probe_flash_headers(read_fn, base_addr: int, total_size: int, label: str) -> bool:
    """Read 16-byte headers across key offsets; return True if any non-zero byte found."""
    if base_addr == 0x00800000:
        offsets = (0x000000, 0x001000, 0x002000, 0x038000, 0x058000, 0x059000, 0x0DC000, 0x0EC000)
    else:
        offsets = (0x000000, 0x000278, 0x0119A0, 0x03D0C0, 0x080000, 0x0B61C0)
    any_nonzero = False
    for off in offsets:
        if off + 16 <= total_size:
            hdr = read_fn(base_addr + off, 16)
            if any(hdr):
                any_nonzero = True
            print(f"    [{label} peek 0x{base_addr + off:08X}]: {hdr.hex(' ')}")
    return any_nonzero


def print_partition_summary(raw: bytes, base_addr: int):
    if base_addr == 0x00000000 and len(raw) >= 64:
        vec_names = [
            "Initial_MSP", "Reset_Handler", "NMI_Handler", "HardFault_Handler",
            "MemManage_Handler", "BusFault_Handler", "UsageFault_Handler", "Reserved_7",
            "Reserved_8", "Reserved_9", "Reserved_10", "SVC_Handler",
            "DebugMon_Handler", "Reserved_13", "PendSV_Handler", "SysTick_Handler",
        ]
        print("\n[+] RTL8763BF Cortex-M4F BootROM / SysROM Vector Table @ 0x00000000:")
        for i, name in enumerate(vec_names):
            val = struct.unpack_from("<I", raw, i * 4)[0]
            if val != 0:
                print(f"    [{i:2d}] +0x{i*4:02X} {name:20s} = 0x{val:08X}")
        used_ff = len(raw.rstrip(b"\xff"))
        used_00 = len(raw.rstrip(b"\x00"))
        print(f"    ROM span: 0x{base_addr:08X}..0x{base_addr + len(raw) - 1:08X} ({len(raw)//1024} KiB), "
              f"last non-0xFF @ +0x{used_ff:06X}, last non-0x00 @ +0x{used_00:06X}")
        return

    if len(raw) < 0x100000 or base_addr != 0x00800000:
        return
    print("\n[+] RTL8763BF (BBPro) 1 MiB Flash Partition Map Summary:")
    for off, sz, name in BBPRO_PARTITIONS:
        seg = raw[off : off + sz]
        used = len(seg.rstrip(b"\xff"))
        hdr8 = seg[:8].hex(" ")
        print(f"    0x{base_addr + off:08X}..0x{base_addr + off + sz - 1:08X} ({sz // 1024:3d} KiB) | {name:34s} | used={used:6d} B | hdr={hdr8}")


def dump_loop(
    read_fn,
    chunk_size: int,
    base_addr: int,
    total_size: int,
    out_path: str,
    resume: bool = False,
) -> bytes:
    part_path = out_path + ".part"
    buf = bytearray()
    if resume and os.path.isfile(part_path):
        existing = Path(part_path).read_bytes()
        if 0 < len(existing) < total_size:
            buf.extend(existing)
            print(f"[*] Resuming from {part_path}: {len(buf):,} / {total_size:,} bytes already saved")

    t0 = time.monotonic()
    last_ckpt = len(buf)
    printed_preview = len(buf) > 0

    while len(buf) < total_size:
        off = len(buf)
        cur_addr = base_addr + off
        req = min(chunk_size, total_size - off)

        for attempt in range(4):
            try:
                chunk = read_fn(cur_addr, req)
                break
            except Exception as exc:
                if attempt == 3:
                    Path(part_path).write_bytes(buf)
                    print(f"\n[!] Saved partial progress ({len(buf):,} B) to {part_path}")
                    raise
                print(f"\n[!] Retry {attempt + 1}/3 @ 0x{cur_addr:08X} ({exc})...")
                time.sleep(0.12)

        if not printed_preview:
            preview = chunk[: min(32, len(chunk))]
            print(f"[+] First {len(preview)} bytes @ 0x{cur_addr:08X}: {preview.hex(' ')}")
            printed_preview = True

        buf.extend(chunk)

        if len(buf) - last_ckpt >= 65536:
            Path(part_path).write_bytes(buf)
            last_ckpt = len(buf)

        done = len(buf)
        elapsed = max(0.001, time.monotonic() - t0)
        rate = (done / 1024.0) / elapsed
        eta = ((total_size - done) / 1024.0) / max(0.05, rate)
        pct = done * 100.0 / total_size
        sys.stdout.write(
            f"\r[*] Dumping 0x{cur_addr:08X}: {done:7d}/{total_size} B "
            f"({pct:5.1f}%) | {rate:5.2f} KiB/s | ETA {eta:5.1f}s   "
        )
        sys.stdout.flush()

    print()
    raw = bytes(buf)
    Path(out_path).write_bytes(raw)
    if os.path.isfile(part_path):
        try:
            os.remove(part_path)
        except OSError:
            pass
    return raw


def main():
    ap = argparse.ArgumentParser(
        description="Dump Realtek RTL8763BF 1 MiB internal flash or 768 KiB BootROM/SysROM over UART"
    )
    ap.add_argument("port", help="Serial port (e.g. COM12 or /dev/ttyUSB0)")
    ap.add_argument("-o", "--output", default=None, help="Output binary path (default: jbl510bt_full_1MB.bin, or rtl8763bf_bootrom_768KB.bin with --rom)")
    ap.add_argument("--rom", action="store_true", help="Dump full 768 KiB BootROM + SysROM (sets --addr 0x00000000 --size 0x000C0000)")
    ap.add_argument("--addr", type=lambda x: int(x, 0), default=None, help="Start address (default: 0x00800000, or 0x00000000 with --rom)")
    ap.add_argument("--size", type=lambda x: int(x, 0), default=None, help="Byte count (default: 0x00100000 = 1 MiB, or 0x000C0000 = 768 KiB with --rom)")
    ap.add_argument(
        "--baud",
        type=int,
        default=115200,
        choices=sorted(BAUD_DIVISORS),
        help="Transfer baudrate (default: 115200 — safest on JBL 510BT because RX shares THM_DET NTC RC network!)",
    )
    ap.add_argument(
        "--mode",
        choices=["auto", "mploader", "fc2d", "fc29"],
        default="auto",
        help="Read mode: auto (0xFD60 unlock -> MP Loader 0x1033 1024B/pkt + CRC16 -> 0xFC2D fallback), mploader, fc2d, or fc29",
    )
    ap.add_argument("--stub", default=None, help="Optional path to Image/firmware3.bin (embedded copy used if omitted)")
    ap.add_argument("--no-raw-hook", action="store_true", help="Do not inject raw CPU bus read hook into firmware3.bin for non-flash addresses")
    ap.add_argument("--skip-unlock", action="store_true", help="Skip 0xFD60 BootROM unlock (if already unlocked)")
    ap.add_argument("--resume", action="store_true", help="Resume from <output>.part if interrupted")
    ap.add_argument("-v", "--verbose", action="store_true", help="Verbose packet hex logging")
    args = ap.parse_args()

    if args.rom:
        if args.addr is None:
            args.addr = ROM_BASE_DEFAULT
        if args.size is None:
            args.size = ROM_SIZE_DEFAULT
        if args.output is None:
            args.output = "rtl8763bf_bootrom_768KB.bin"
    else:
        if args.addr is None:
            args.addr = FLASH_BASE_DEFAULT
        if args.size is None:
            args.size = FLASH_SIZE_DEFAULT
        if args.output is None:
            args.output = (
                "rtl8763bf_bootrom_768KB.bin"
                if (args.addr == ROM_BASE_DEFAULT and args.size == ROM_SIZE_DEFAULT)
                else "jbl510bt_full_1MB.bin"
            )

    need_raw_cpu_bus = not is_spi_flash_region(args.addr, args.size)

    print(
        f"[*] Target region: 0x{args.addr:08X} .. 0x{args.addr + args.size - 1:08X} "
        f"({args.size:,} B = {args.size / 1024:.1f} KiB) -> {args.output}"
    )
    print(f"[*] Opening {args.port} @ 115200 8N1...")
    dumper = Rtl8763Dumper(args.port, init_baud=115200, verbose=args.verbose)

    try:
        # 1. Handshake with BootROM HCI (or detect already-running MP Loader!)
        ver = None
        rom_ver = None
        xtal_cfg = 0x1B
        efuse_key = RTL8763BF_DEFAULT_EFUSE_KEY
        golden_16b = None

        try:
            ver = dumper.read_local_version()
        except TimeoutError:
            print("[*] No H4 HCI reply @ 115200 — checking if MP Loader (0x87) is already active...")
            try:
                probe_addr = FLASH_BASE_DEFAULT if need_raw_cpu_bus else args.addr
                probe = dumper.mp_flash_read(probe_addr, 16)
                dumper.in_mp_loader = True
                print(f"[+] Chip is ALREADY in MP Loader mode! Probe @ 0x{probe_addr:08X}: {probe.hex(' ')}")
            except Exception:
                print(
                    "[-] No response in HCI or MP Loader mode.\n"
                    "    Checklist:\n"
                    "      1. Power OFF the PCB completely (unplug USB & battery or wait for full power-off).\n"
                    "      2. Hold LOG (P2_0, Pin 33) shorted to GND.\n"
                    "      3. Power ON the PCB while LOG is held to GND.\n"
                    "      4. Verify TX (P0_7)->Adapter RX and RX (P0_6/THM_DET)->Adapter TX.",
                    file=sys.stderr,
                )
                sys.exit(2)

        if ver is not None:
            print(
                f"[+] BootROM HCI connected: Manufacturer=0x{ver['manufacturer']:04X} (Realtek=0x005D), "
                f"LMP Subversion=0x{ver['lmp_subver']:04X}, HCI Rev=0x{ver['hci_rev']:04X}"
            )
            try:
                rom_ver = dumper.read_rom_version()
                print(f"[+] ROM Version (0xFC6D): 0x{rom_ver:02X} (RTL8763BF Cut {rom_ver + 1})")
            except Exception as e:
                print(f"[*] 0xFC6D skipped ({e})")

            try:
                xtal_cfg = dumper.read_xtal_cfg()
                lock_a = dumper.read_mem32_fc29(0x1000509C)
                lock_b = dumper.read_mem32_fc29(0x100050A0) & 0xFFFF
                lock_bytes = struct.pack("<IH", lock_a, lock_b)
                efuse_key = b"".join(struct.pack("<I", dumper.read_mem32_fc29(0x100050D0 + i)) for i in range(0, 16, 4))
                locked = (lock_bytes != b"\xff\xff\xff\xff\x00\xff")
                key_tag = "factory default" if efuse_key == RTL8763BF_DEFAULT_EFUSE_KEY else "custom OEM"
                print(
                    f"[+] eFuse (0xFC29): XTAL_cfg=0x{xtal_cfg:02X} | "
                    f"Key={efuse_key.hex()} ({key_tag}) | "
                    f"ReadProtect={'LOCKED' if locked else 'OPEN'} ({lock_bytes.hex()})"
                )
            except Exception as e:
                print(f"[*] Optional eFuse read (0xFC29) skipped ({e}); using factory defaults")

            # Capture 16-byte golden CPU-bus reference via BootROM 0xFC29 when dumping ROM/RAM
            if need_raw_cpu_bus and (args.addr & 3) == 0 and args.size >= 16:
                try:
                    golden_16b = b"".join(
                        struct.pack("<I", dumper.read_mem32_fc29(args.addr + i)) for i in range(0, 16, 4)
                    )
                    if args.addr == 0x00000000:
                        msp, rst, nmi, hf = struct.unpack("<4I", golden_16b)
                        print(
                            f"[+] BootROM CPU-bus vector (0xFC29 @ 0x00000000): "
                            f"MSP=0x{msp:08X}, Reset=0x{rst:08X}, NMI=0x{nmi:08X}, HardFault=0x{hf:08X}"
                        )
                    else:
                        print(f"[+] Golden CPU-bus head (0xFC29 @ 0x{args.addr:08X}): {golden_16b.hex(' ')}")
                except Exception as e:
                    print(f"[*] Golden 0xFC29 read @ 0x{args.addr:08X} skipped ({e})")

            # 2. Execute mandatory RTL8763BF (IC == 5, rom_ver == 0x04) BootROM AES-128 Unlock (0xFD60 NoAck)!
            if not args.skip_unlock and ver["lmp_subver"] == 0x8763 and (rom_ver is None or rom_ver == 0x04):
                dumper.unlock_rtl8763bf_bootrom(efuse_key, xtal_cfg)

        # 3. Select transport & execute dump
        raw = None

        # Path 0: Already inside MP Loader from an earlier run without power-cycle
        if dumper.in_mp_loader:
            if args.baud != 115200:
                print(f"[*] Switching MP Loader baudrate to {args.baud} (0x1010)...")
                dumper.mp_switch_baudrate(args.baud)
            try:
                head16 = dumper.mp_flash_read(args.addr, 16)
                if need_raw_cpu_bus and args.addr < 0x00400000:
                    fl16 = dumper.mp_flash_read(FLASH_BASE_DEFAULT + args.addr, 16)
                    if head16 == fl16:
                        raise RuntimeError(
                            "Already-loaded stock MP Loader is mirroring SPI Flash (0x00800000) instead of CPU ROM! "
                            "Power-cycle PCB with LOG->GND and re-run so the raw CPU-bus hook is uploaded."
                        )
            except Exception as e:
                raise RuntimeError(
                    f"Already-loaded stock MP Loader cannot read 0x{args.addr:08X} directly ({e}). "
                    f"Power-cycle PCB with LOG->GND and re-run so dump_jbl510bt.py uploads the raw CPU-bus hook!"
                ) from e
            probe_flash_headers(dumper.mp_flash_read, args.addr, args.size, "MP 0x1033")
            print("[*] Dumping via MP Loader (0x87 / cmd 0x1033, 1024 B/pkt + CRC-16)...")
            raw = dump_loop(dumper.mp_flash_read, 1024, args.addr, args.size, args.output, args.resume)

        else:
            # Quick diagnostic peek via BootROM 0xFC2D right after 0xFD60 unlock
            fc2d_nonzero = False
            fc2d_matches_golden = True
            if args.mode in ("auto", "fc2d") and not need_raw_cpu_bus:
                try:
                    print("[*] Probing flash partition headers via BootROM 0xFC2D post-unlock...")
                    fc2d_nonzero = probe_flash_headers(dumper.flash_read_fc2d, args.addr, args.size, "HCI 0xFC2D")
                except Exception as e:
                    print(f"[*] BootROM 0xFC2D probe skipped ({e})")
            elif args.mode == "fc2d" and need_raw_cpu_bus:
                try:
                    h16 = dumper.flash_read_fc2d(args.addr, 16)
                    fc2d_nonzero = any(h16)
                    if golden_16b is not None and h16 != golden_16b:
                        fc2d_matches_golden = False
                        print(
                            f"[!] WARNING: 0xFC2D @ 0x{args.addr:08X} ({h16.hex()}) != 0xFC29 CPU bus ({golden_16b.hex()})! "
                            f"0xFC2D accesses SPIC flash, not CPU ROM — use --mode auto (MP raw CPU-bus hook) or --mode fc29!"
                        )
                except Exception as e:
                    print(f"[*] BootROM 0xFC2D probe failed ({e})")

            # Primary Path on RTL8763BF:
            # - For SPI Flash (0x00800000): unpatched Image/firmware3.bin -> flash_nor_init + dfu_mp_read_flash.
            # - For ROM/RAM (<0x00800000 or >=0x00C00000): Image/firmware3.bin + 98B raw CPU-bus read hook @ 0x10081570!
            if args.mode in ("auto", "mploader"):
                try:
                    fw_bytes, fw_src = load_firmware3_bytes(args.stub)
                    if need_raw_cpu_bus and not args.no_raw_hook and args.stub is None:
                        fw_bytes = patch_firmware3_raw_cpu_read(fw_bytes)
                        fw_src += " + raw CPU-bus read hook @ 0x10081570"
                    print(f"[*] Uploading {fw_src} ({len(fw_bytes)} B) to 0x10080C00 via 0xFC20 + 0xFC62...")
                    dumper.upload_and_start_mp_loader(fw_bytes)
                    if args.baud != 115200:
                        print(f"[*] Switching MP Loader baudrate to {args.baud} (0x1010)...")
                        dumper.mp_switch_baudrate(args.baud)
                    if golden_16b is not None:
                        mp_head16 = dumper.mp_flash_read(args.addr, 16)
                        if mp_head16 != golden_16b:
                            raise RuntimeError(
                                f"MP 0x1033 @ 0x{args.addr:08X} ({mp_head16.hex()}) != 0xFC29 golden vector ({golden_16b.hex()})"
                            )
                        print(f"[+] Verified MP 0x1033 @ 0x{args.addr:08X} matches 0xFC29 CPU-bus golden vector bit-for-bit!")
                    mp_nonzero = probe_flash_headers(dumper.mp_flash_read, args.addr, args.size, "MP 0x1033")
                    if not mp_nonzero:
                        print("[!] WARNING: MP Loader 0x1033 probes are all 0x00!")
                    print("[+] MP Loader (0x87 / cmd 0x1033) online! Dumping @ 1024 B/pkt + CRC-16/ARC...")
                    raw = dump_loop(dumper.mp_flash_read, 1024, args.addr, args.size, args.output, args.resume)
                except Exception as e:
                    if args.mode == "mploader":
                        raise
                    if dumper.in_mp_loader and fc2d_nonzero and not need_raw_cpu_bus:
                        raise RuntimeError(
                            f"MP Loader did not respond after 0xFC62 ({e}), BUT BootROM 0xFC2D already read "
                            f"valid non-zero flash post-0xFD60! Power-cycle PCB (LOG->GND) and run: "
                            f"python {Path(sys.argv[0]).name} {args.port} --mode fc2d -o {args.output}"
                        ) from e
                    print(f"[!] MP Loader path failed ({e}) -> falling back...")

            # Fallback / Explicit --mode fc2d: Pure BootROM HCI 0xFC2D (244 B/pkt)
            if raw is None and args.mode in ("auto", "fc2d") and not dumper.in_mp_loader and fc2d_matches_golden and not need_raw_cpu_bus:
                if args.mode == "auto" and not fc2d_nonzero:
                    raise RuntimeError(
                        "Both MP Loader failed and BootROM 0xFC2D returned all-0x00 (SPIC uninitialized). "
                        "Power-cycle PCB with LOG->GND and re-run with -v."
                    )
                if args.baud != 115200 and dumper.ser.baudrate != args.baud:
                    print(f"[*] Switching BootROM HCI baudrate to {args.baud} (0xFC17)...")
                    dumper.switch_baudrate_hci(args.baud)
                print("[+] Dumping via BootROM HCI 0xFC2D @ 244 B/pkt...")
                raw = dump_loop(dumper.flash_read_fc2d, 0xF4, args.addr, args.size, args.output, args.resume)
            elif raw is None and args.mode == "fc2d" and need_raw_cpu_bus and fc2d_matches_golden:
                if args.baud != 115200 and dumper.ser.baudrate != args.baud:
                    dumper.switch_baudrate_hci(args.baud)
                print("[+] Dumping via BootROM HCI 0xFC2D @ 244 B/pkt...")
                raw = dump_loop(dumper.flash_read_fc2d, 0xF4, args.addr, args.size, args.output, args.resume)

            # Explicit --mode fc29 (or ultimate fallback for CPU-bus ROM/RAM if MP Loader failed before 0xFC62)
            if raw is None and (args.mode == "fc29" or (args.mode == "auto" and need_raw_cpu_bus and not dumper.in_mp_loader)):
                if args.baud != 115200 and dumper.ser.baudrate != args.baud:
                    dumper.switch_baudrate_hci(args.baud)

                def _read_fc29_block(a: int, n: int) -> bytes:
                    out = bytearray()
                    for off in range(0, n, 4):
                        w = dumper.read_mem32_fc29(a + off)
                        out.extend(struct.pack("<I", w)[: min(4, n - off)])
                    return bytes(out)

                print("[*] Dumping via pure BootROM 0xFC29 (4 B/pkt direct CPU-bus read)...")
                raw = dump_loop(_read_fc29_block, 64, args.addr, args.size, args.output, args.resume)

        if raw is None:
            raise RuntimeError("No dump path succeeded; power-cycle PCB (LOG->GND) and retry with -v.")

        sha = hashlib.sha256(raw).hexdigest()
        non_ff = sum(1 for b in raw if b != 0xFF)
        non_00 = sum(1 for b in raw if b != 0x00)
        print(f"[+] Saved {len(raw):,} bytes to {args.output}")
        print(f"[+] SHA-256: {sha}")
        print(f"[+] Sanity: non-0xFF={non_ff:,}/{len(raw):,} B, non-0x00={non_00:,}/{len(raw):,} B")
        if non_ff == 0 or non_00 == 0:
            print("[!] WARNING: Dump appears uniform (all 0xFF or all 0x00)!")
        else:
            print_partition_summary(raw, args.addr)

    finally:
        dumper.close()


if __name__ == "__main__":
    main()
