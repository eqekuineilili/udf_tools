#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# !/usr/bin/env python3
# -*- coding: utf-8 -*-

import struct
import sys
from pathlib import Path
from typing import List, Tuple
from wcwidth import wcswidth


# 核心常量
UDF_SECTOR_SIZE = 512
EFE_TAG_ID = 266
# 预生成的 CRC 表（多项式 0x1021）
crc_table = [
    0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50A5, 0x60C6, 0x70E7,
    0x8108, 0x9129, 0xA14A, 0xB16B, 0xC18C, 0xD1AD, 0xE1CE, 0xF1EF,
    0x1231, 0x0210, 0x3273, 0x2252, 0x52B5, 0x4294, 0x72F7, 0x62D6,
    0x9339, 0x8318, 0xB37B, 0xA35A, 0xD3BD, 0xC39C, 0xF3FF, 0xE3DE,
    0x2462, 0x3443, 0x0420, 0x1401, 0x64E6, 0x74C7, 0x44A4, 0x5485,
    0xA56A, 0xB54B, 0x8528, 0x9509, 0xE5EE, 0xF5CF, 0xC5AC, 0xD58D,
    0x3653, 0x2672, 0x1611, 0x0630, 0x76D7, 0x66F6, 0x5695, 0x46B4,
    0xB75B, 0xA77A, 0x9719, 0x8738, 0xF7DF, 0xE7FE, 0xD79D, 0xC7BC,
    0x48C4, 0x58E5, 0x6886, 0x78A7, 0x0840, 0x1861, 0x2802, 0x3823,
    0xC9CC, 0xD9ED, 0xE98E, 0xF9AF, 0x8948, 0x9969, 0xA90A, 0xB92B,
    0x5AF5, 0x4AD4, 0x7AB7, 0x6A96, 0x1A71, 0x0A50, 0x3A33, 0x2A12,
    0xDBFD, 0xCBDC, 0xFBBF, 0xEB9E, 0x9B79, 0x8B58, 0xBB3B, 0xAB1A,
    0x6CA6, 0x7C87, 0x4CE4, 0x5CC5, 0x2C22, 0x3C03, 0x0C60, 0x1C41,
    0xEDAE, 0xFD8F, 0xCDEC, 0xDDCD, 0xAD2A, 0xBD0B, 0x8D68, 0x9D49,
    0x7E97, 0x6EB6, 0x5ED5, 0x4EF4, 0x3E13, 0x2E32, 0x1E51, 0x0E70,
    0xFF9F, 0xEFBE, 0xDFDD, 0xCFFC, 0xBF1B, 0xAF3A, 0x9F59, 0x8F78,
    0x9188, 0x81A9, 0xB1CA, 0xA1EB, 0xD10C, 0xC12D, 0xF14E, 0xE16F,
    0x1080, 0x00A1, 0x30C2, 0x20E3, 0x5004, 0x4025, 0x7046, 0x6067,
    0x83B9, 0x9398, 0xA3FB, 0xB3DA, 0xC33D, 0xD31C, 0xE37F, 0xF35E,
    0x02B1, 0x1290, 0x22F3, 0x32D2, 0x4235, 0x5214, 0x6277, 0x7256,
    0xB5EA, 0xA5CB, 0x95A8, 0x8589, 0xF56E, 0xE54F, 0xD52C, 0xC50D,
    0x34E2, 0x24C3, 0x14A0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405,
    0xA7DB, 0xB7FA, 0x8799, 0x97B8, 0xE75F, 0xF77E, 0xC71D, 0xD73C,
    0x26D3, 0x36F2, 0x0691, 0x16B0, 0x6657, 0x7676, 0x4615, 0x5634,
    0xD94C, 0xC96D, 0xF90E, 0xE92F, 0x99C8, 0x89E9, 0xB98A, 0xA9AB,
    0x5844, 0x4865, 0x7806, 0x6827, 0x18C0, 0x08E1, 0x3882, 0x28A3,
    0xCB7D, 0xDB5C, 0xEB3F, 0xFB1E, 0x8BF9, 0x9BD8, 0xABBB, 0xBB9A,
    0x4A75, 0x5A54, 0x6A37, 0x7A16, 0x0AF1, 0x1AD0, 0x2AB3, 0x3A92,
    0xFD2E, 0xED0F, 0xDD6C, 0xCD4D, 0xBDAA, 0xAD8B, 0x9DE8, 0x8DC9,
    0x7C26, 0x6C07, 0x5C64, 0x4C45, 0x3CA2, 0x2C83, 0x1CE0, 0x0CC1,
    0xEF1F, 0xFF3E, 0xCF5D, 0xDF7C, 0xAF9B, 0xBFBA, 0x8FD9, 0x9FF8,
    0x6E17, 0x7E36, 0x4E55, 0x5E74, 0x2E93, 0x3EB2, 0x0ED1, 0x1EF0
]


def calc_crc(data: bytes) -> int:
    """
    CRC-16-CCITT实现
    """
    crc = 0x0000
    for byte in data:
        crc = crc_table[((crc >> 8) ^ byte) & 0xFF] ^ ((crc << 8) & 0xFFFF)
    return crc & 0xFFFF


def calc_checksum(tag_bytes: bytes) -> int:

    if len(tag_bytes) != 16:
        raise ValueError("Tag必须是16字节")
    tag_sum = 0
    for i in range(len(tag_bytes)):
        if i == 4:  # 跳过 offset 4 的 TagChecksum 字段
            continue
        tag_sum += tag_bytes[i]
    cksum = tag_sum % 256
    return cksum


def unicode_calc_crc(data: bytes) -> int:
    """
    完全匹配ECMA-167标准的Unicode校验和实现
    按大端字节序处理每个16位字符
    """
    if len(data) % 2 != 0:
        raise ValueError("Unicode校验和数据长度必须为偶数")

    crc = 0x0000
    for i in range(0, len(data), 2):
        # 先处理高字节（大端）
        high_byte = data[i]
        crc = crc_table[((crc >> 8) ^ high_byte) & 0xFF] ^ ((crc << 8) & 0xFFFF)
        # 再处理低字节
        low_byte = data[i + 1]
        crc = crc_table[((crc >> 8) ^ low_byte) & 0xFF] ^ ((crc << 8) & 0xFFFF)
    return crc & 0xFFFF



def descriptor_data(efe_raw: bytes, base_offset: int = 0) -> Tuple[bytes, List[bytes]]:
    embedded_fids = []

    efe_crc_length = struct.unpack('<H', efe_raw[10:12])[0]
    efe_bytes = efe_raw[:efe_crc_length+16]

    # 2. 提取内嵌FID（仅当AD Type=3时）
    if len(efe_raw) < 216:
        return efe_bytes, embedded_fids

    # 读取动态长度字段
    L_EA = struct.unpack('<I', efe_raw[208:212])[0]
    L_AD = struct.unpack('<I', efe_raw[212:216])[0]

    # 定位Allocation Descriptors区域
    ad_base = 216 + L_EA
    ad_end = ad_base + L_AD

    if ad_end > len(efe_raw):
        return efe_bytes, embedded_fids

    ad_data = efe_raw[ad_base:ad_end]

    # 读取ICB Tag判断AD类型
    icb_tag = efe_raw[16:36]
    if len(icb_tag) < 20:
        return efe_bytes, embedded_fids

    flags = struct.unpack('<H', icb_tag[18:20])[0]
    ad_type = flags & 0x07
    if ad_type != 3:
        return efe_bytes, embedded_fids

    # ==================================================
    # 按照 ECMA-167  定义的 FID 结构
    # RBP     | 长度 | 字段名
    # 0       | 16   | Descriptor Tag
    # 16      | 2    | File Version Number
    # 18      | 1    | File Characteristics
    # 19      | 1    | Length of File Identifier (L_FI)
    # 20      | 16   | ICB (long_ad)
    # 36      | 2    | Length of Implementation Use (L_IU)
    # 38      | L_IU | Implementation Use
    # 38+L_IU | L_FI | File Identifier
    # 末尾     |      | Padding (4字节对齐)
    # ==================================================

    # 循环提取所有内嵌FID
    offset = 0
    while offset < len(ad_data):
        if len(ad_data) - offset < 38:
            break

        # 读取FID固定头计算总长度
        fid_fixed = ad_data[offset:offset + 38]
        L_FI = struct.unpack('<B', fid_fixed[19:20])[0]
        L_IU = struct.unpack('<H', fid_fixed[36:38])[0]

        # 计算FID总长度（含4字节对齐填充，严格遵循UDF标准）
        raw_len = 38 + L_FI + L_IU
        padding_len = 4 * ((raw_len + 3) // 4) - raw_len
        fid_total_len = raw_len + padding_len

        if offset + fid_total_len > len(ad_data):
            break

        # 提取完整FID原始数据（仅保留bytes）
        fid_raw = ad_data[offset:offset + fid_total_len]
        fid_crc_length = struct.unpack('<H', fid_raw[10:12])[0]
        if len(fid_raw) == (16+fid_crc_length):
            embedded_fids.append(fid_raw)
        offset += fid_total_len

    return efe_bytes, embedded_fids


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("请提供文件名作为命令行参数！python3 py-volume-structure.py blank-volume-structure.hex")
        sys.exit(1)

    filename = sys.argv[1]
    hex_file = Path(filename)
    if not hex_file.exists():
        raise SystemExit(f'未找到文件: {filename}')

    file_data = bytearray(hex_file.read_bytes())
    print(f"成功读取文件：{filename}，长度：{len(file_data)} 字节\n")
    writeback_data = bytearray()
    total_blocks = len(file_data) // UDF_SECTOR_SIZE
    print("=" * 80)
    print(f"解析文件: {hex_file}")
    print(f"文件总大小: {len(file_data)} 字节 ({total_blocks} 个512字节块)")
    print("=" * 80)

    efe_count = 0
    for block_idx in range(total_blocks):
        # 计算当前块的偏移和数据
        block_offset = block_idx * UDF_SECTOR_SIZE
        block_data = file_data[block_offset: block_offset + UDF_SECTOR_SIZE]

        # 检查是否为EFE（Tag ID=266）
        tag_id = struct.unpack('<H', block_data[0:2])[0]
        if tag_id == EFE_TAG_ID:
            efe_count += 1
            print(f"\n\n{'=' * 80}")
            print(f"[发现EFE] 块 #{block_idx} (文件偏移: 0x{block_offset:X})")
            print(f"{'=' * 80}")

            efe_data, fids = descriptor_data(block_data, block_offset)

            print(f"\n--- [1/2] 内嵌FID CRC 数据 (共{len(fids)}个) ---")
            writeback_fid_data = bytearray()
            if fids:
                for i, fid_data in enumerate(fids):
                    fid_tag_bytes = bytearray(fid_data[:16])
                    fid_crc_length = struct.unpack('<H', fid_tag_bytes[10:12])[0]
                    fid_crc_bytes = fid_data[16:fid_crc_length + 16]

                    print(f"\n  FID #{i}:")
                    print(f"    CRC校验长度: {fid_crc_length} 字节")
                    print(f"    校验数据 (Hex): {fid_crc_bytes.hex().upper()}")
                    print(f"    Descriptor CRC (Byte): {calc_crc(fid_crc_bytes):04X}")

                    fid_crc_low = calc_crc(fid_crc_bytes) & 0xFF
                    fid_crc_high = (calc_crc(fid_crc_bytes) >> 8) & 0xFF
                    fid_tag_bytes[8] = fid_crc_low
                    fid_tag_bytes[9] = fid_crc_high
                    print(f"    更新CRC (Byte): {fid_tag_bytes.hex().upper()}")
                    fid_tag_checksum = calc_checksum(fid_tag_bytes)
                    fid_tag_bytes[4] = fid_tag_checksum
                    print(f"    更新checksum (Byte): {fid_tag_bytes.hex().upper()}")
                    temp_fid = fid_tag_bytes + fid_crc_bytes
                    writeback_fid_data.extend(temp_fid)
            else:
                print("  未发现内嵌FID (AD Type != 3 或 L_AD=0)")
            if len(block_data) > 216 and writeback_fid_data:
                # 读取动态长度字段
                L_EA = struct.unpack('<I', block_data[208:212])[0]
                L_AD = struct.unpack('<I', block_data[212:216])[0]
                # 定位Allocation Descriptors区域
                ad_base = 216 + L_EA
                block_data[ad_base:ad_base + len(writeback_fid_data)] = writeback_fid_data

            efe_data, fids = descriptor_data(block_data, block_offset)
            print("\n--- [2/2] EFE CRC 数据 ---")
            if efe_data:
                efe_tag_bytes = bytearray(efe_data[:16])
                efe_crc_length = struct.unpack('<H', efe_tag_bytes[10:12])[0]
                efe_crc_bytes = efe_data[16:efe_crc_length + 16]

                print(f"CRC校验长度: {efe_crc_length} 字节")
                print(f"校验数据 (Hex): {efe_crc_bytes.hex().upper()}")
                print(f"Descriptor CRC (Byte): {calc_crc(efe_crc_bytes):04X}")

                efe_crc_low = calc_crc(efe_crc_bytes) & 0xFF
                efe_crc_high = (calc_crc(efe_crc_bytes) >> 8) & 0xFF
                efe_tag_bytes[8] = efe_crc_low
                efe_tag_bytes[9] = efe_crc_high
                print(f"    更新CRC (Byte): {efe_tag_bytes.hex()}")
                efe_tag_checksum = calc_checksum(efe_tag_bytes)
                efe_tag_bytes[4] = efe_tag_checksum
                print(f"    更新checksum (Byte): {efe_tag_bytes.hex().upper()}")
                writeback_efe_data = efe_tag_bytes + efe_crc_bytes
            else:
                print("未提取到有效EFE CRC数据")

            if len(writeback_efe_data) % UDF_SECTOR_SIZE != 0:
                writeback_efe_data.extend(b'\x00' * (UDF_SECTOR_SIZE - len(writeback_efe_data)))
            writeback_data.extend(writeback_efe_data)
        else:
            break

    print(f"\n\n{'=' * 80}")
    print(f"处理完成: 共扫描 {total_blocks} 个块, 发现 {efe_count} 个EFE")
    if writeback_data:
        output_filename = f"{filename}-writeback.hex"
        output_path = Path(output_filename)
        output_path.write_bytes(writeback_data)
        print(f"已将修正数据写入: {output_filename}")
    print(f"{'=' * 80}")

