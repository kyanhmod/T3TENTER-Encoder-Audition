#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
Audition Global IP Tool (Công cụ Mã hóa & Giải mã IP Audition Global)
================================================================================
Dành riêng cho các phiên bản Audition sử dụng chuẩn mã hóa Hex Dynamic XOR:
  - Audition Global (Redbana / PlayData)
  - Audition Latam (Axeso5)
  - Audition Private Servers (PVS)
  - Audition VTC
================================================================================
"""

import sys
import os
import argparse
import random
import re
from typing import Optional, Tuple

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

def rol8(val: int, r: int) -> int:
    return ((val << (r % 8)) & 0xFF) | ((val & 0xFF) >> (8 - (r % 8)))

def ror8(val: int, r: int) -> int:
    return ((val & 0xFF) >> (r % 8)) | ((val << (8 - (r % 8))) & 0xFF)

def is_valid_ipv4(ip_str: str) -> bool:
    parts = ip_str.strip().split(".")
    if len(parts) != 4:
        return False
    for p in parts:
        if not p.isdigit():
            return False
        num = int(p)
        if num < 0 or num > 255:
            return False
        if len(p) > 1 and p.startswith("0"):
            return False
    return True

def encode_ip(ip_str: str, key: Optional[bytes] = None) -> str:
    """
    Mã hóa IP sang Token Hex /T3ENTER chuẩn Audition Global.
    Cấu trúc: [2B TotalLen] + [1B EncodedKeyLen] + [3B Key] + [Ciphertext]
    """
    if not is_valid_ipv4(ip_str):
        raise ValueError(f"Địa chỉ IP không hợp lệ: '{ip_str}'")

    plain = ip_str.strip().encode("ascii")
    length = len(plain)

    if key is None or len(key) == 0:
        key_len = 3
        key = bytes(random.randint(1, 254) for _ in range(key_len))
    else:
        key_len = len(key)
        if key_len > 15:
            key = key[:15]
            key_len = 15

    cipher = bytearray(length)
    for i in range(length):
        cipher[i] = plain[i] ^ key[i % key_len] ^ (length - i)

    encoded_klen = (~rol8(key_len, 7)) & 0xFF
    body = bytes([encoded_klen]) + key + bytes(cipher)
    total_len = len(body) + 2
    header = bytes([total_len & 0xFF, (total_len >> 8) & 0xFF])

    return (header + body).hex().upper()

def decode_token(token: str) -> Tuple[bool, str, str]:
    """
    Giải mã Token Hex /T3ENTER ra IP gốc.
    """
    token = token.strip()
    if token.upper().startswith("/T3ENTER"):
        token = token[8:].strip()

    if len(token) % 2 != 0 or not re.fullmatch(r"[0-9a-fA-F]+", token):
        return False, "", "Token không phải chuỗi Hex hợp lệ"

    try:
        raw = bytes.fromhex(token)
    except ValueError:
        return False, "", "Lỗi đọc dữ liệu Hex"

    # Chuẩn Global có 2 byte header
    if len(raw) >= 5:
        w = raw[0] | (raw[1] << 8)
        if w == len(raw) or w == len(raw) - 2:
            klen_byte = raw[2]
            klen = ror8((~klen_byte) & 0xFF, 7)
            if 1 <= klen <= 16 and len(raw) > 3 + klen:
                key = raw[3 : 3 + klen]
                cipher = raw[3 + klen :]
                L = len(cipher)
                plain = bytearray(L)
                for i in range(L):
                    plain[i] = cipher[i] ^ key[i % klen] ^ (L - i)
                try:
                    ip_str = plain.decode("ascii")
                    if is_valid_ipv4(ip_str):
                        return True, ip_str, f"KeyLen={klen}"
                except UnicodeDecodeError:
                    pass

    # Fallback cho token không có 2 byte header
    if len(raw) >= 3:
        klen1 = ror8((~raw[0]) & 0xFF, 7)
        if 1 <= klen1 <= 16 and len(raw) > 1 + klen1:
            key1 = raw[1 : 1 + klen1]
            cipher1 = raw[1 + klen1 :]
            L1 = len(cipher1)
            plain1 = bytearray(L1)
            for i in range(L1):
                plain1[i] = cipher1[i] ^ key1[i % klen1] ^ (L1 - i)
            try:
                ip_str1 = plain1.decode("ascii")
                if is_valid_ipv4(ip_str1):
                    return True, ip_str1, f"Raw KeyLen={klen1}"
            except UnicodeDecodeError:
                pass

    return False, "", "Không thể giải mã Token này"

def interactive_mode():
    banner = r"""
================================================================================
       AUDITION GLOBAL IP CODEC (PVS / LATAM / REDBANA / VTC)
================================================================================
"""
    print(banner)
    while True:
        print("\n--- MENU ---")
        print("1. Mã hóa IP sang Token /T3ENTER")
        print("2. Giải mã Token ra IP")
        print("3. Tạo file start_game.bat")
        print("0. Thoát")

        choice = input("\nChọn (0-3): ").strip()
        if choice == "0":
            print("Tạm biệt!")
            break
        elif choice == "1":
            ip = input("Nhập IP máy chủ (VD: 127.0.0.1): ").strip()
            if not is_valid_ipv4(ip):
                print(f"[!] Lỗi: IP '{ip}' không đúng định dạng!")
                continue
            token = encode_ip(ip)
            print("\n" + "=" * 60)
            print(f"[+] IP Máy Chủ : {ip}")
            print(f"[+] Token Hex  : {token}")
            print(f"[+] Lệnh chạy  : Audition.exe /T3ENTER {token}")
            print("=" * 60)
        elif choice == "2":
            tok = input("Nhập Token Hex (hoặc cả chuỗi /t3enter ...): ").strip()
            if not tok:
                continue
            ok, ip, desc = decode_token(tok)
            print("\n" + "=" * 60)
            if ok:
                print(f"[OK] Giải mã thành công!")
                print(f"     IP Máy Chủ : {ip}")
                print(f"     Thông số   : {desc}")
            else:
                print(f"[!] Thất bại: {desc}")
            print("=" * 60)
        elif choice == "3":
            ip = input("Nhập IP máy chủ (VD: 127.0.0.1): ").strip()
            if not is_valid_ipv4(ip):
                print(f"[!] Lỗi: IP '{ip}' không hợp lệ!")
                continue
            exe_name = input("Tên file client (mặc định Audition.exe): ").strip() or "Audition.exe"
            token = encode_ip(ip)
            bat_name = "start_game.bat"
            content = f"@echo off\r\necho Dang khoi dong {exe_name} toi {ip}...\r\nstart \"\" \"{exe_name}\" /T3ENTER {token}\r\n"
            with open(bat_name, "w", encoding="ascii") as f:
                f.write(content)
            print(f"[OK] Đã tạo file '{bat_name}':")
            print(f"     start \"\" \"{exe_name}\" /T3ENTER {token}")
        else:
            print("[!] Lựa chọn không hợp lệ!")

def main():
    if len(sys.argv) == 1:
        interactive_mode()
        return

    # Nếu truyền 1 tham số duy nhất và là IP
    if len(sys.argv) == 2 and is_valid_ipv4(sys.argv[1]):
        ip = sys.argv[1]
        token = encode_ip(ip)
        print(f"Token: {token}")
        print(f"Launch: Audition.exe /T3ENTER {token}")
        return

    parser = argparse.ArgumentParser(
        description="Audition Global IP Tool - Mã hóa & giải mã IP cho Audition Global / PVS / Latam / Redbana / VTC."
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("ip", nargs="?", help="IP cần mã hóa (VD: 127.0.0.1)")
    group.add_argument("-d", "--decode", metavar="TOKEN", help="Giải mã token ra IP")
    
    parser.add_argument("-b", "--bat", metavar="EXE_NAME", nargs="?", const="Audition.exe",
                        help="Tự động tạo file start_game.bat (mặc định dùng Audition.exe)")

    args = parser.parse_args()

    if args.decode:
        ok, ip, desc = decode_token(args.decode)
        if ok:
            print(f"[OK] IP: {ip} ({desc})")
        else:
            print(f"[!] Lỗi: {desc}")
            sys.exit(1)
    elif args.ip:
        if not is_valid_ipv4(args.ip):
            print(f"[!] Lỗi: IP '{args.ip}' không hợp lệ!")
            sys.exit(1)
        token = encode_ip(args.ip)
        print(f"[+] IP    : {args.ip}")
        print(f"[+] Token : {token}")
        print(f"[+] Lệnh  : Audition.exe /T3ENTER {token}")
        if args.bat:
            with open("start_game.bat", "w", encoding="ascii") as f:
                f.write(f"@echo off\r\nstart \"\" \"{args.bat}\" /T3ENTER {token}\r\n")
            print(f"[OK] Đã tạo file start_game.bat khởi động '{args.bat}'")

if __name__ == "__main__":
    main()
