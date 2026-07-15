#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
python udf_rename.py  <img>  <fid_offset>  "新名字"
"""
import sys
import struct
from pathlib import Path

UDF_SECTOR_SIZE = 512


def dstring_to_str(b: bytes) -> str:
    """UDF dstring 格式解析（ASCII，尾部补0）"""
    if not b:
        return ""
    comp_id = b[0]
    if comp_id == 0x08:
        return b[1:].decode('ascii', errors='replace')
    elif comp_id == 0x10:
        return b[1:].decode('utf-16be', errors='replace')
    return f"<未知前缀 0x{comp_id:02X}>"


def lb_addr_to_str(b: bytes) -> str:
    """UDF 6字节 lb_addr 解析（4字节逻辑块号 + 2字节分区引用）"""
    if len(b) != 6:
        return f"无效lb_addr（长度={len(b)}，标准要求6字节）"
    LogicalBlockNumber = struct.unpack('<I', b[0:4])[0]
    PartitionReferenceNumber = struct.unpack('<H', b[4:6])[0]
    return f"分区={PartitionReferenceNumber}, 逻辑块={LogicalBlockNumber}"


def long_ad_to_str(b: bytes) -> str:
    if len(b) != 16:
        return f"无效长分配描述符（长度={len(b)}，标准要求16字节）"
    length = struct.unpack('<I', b[0:4])[0]
    position = lb_addr_to_str(b[4:10])
    ImplementationUse = b[10:16].hex()
    return f"长度={length}字节, 地址=[{position}], 实现使用={ImplementationUse}"


def get_udf_filename(s: str) -> bytes:
    try:
        # 尝试纯 ASCII
        return b'\x08' + s.encode('ascii')
    except UnicodeEncodeError:
        # 有中文，用 UTF-16BE
        return b'\x10' + s.encode('utf-16be')


def rename_embedded_fid(hex_path: Path, efe_offset: int, new_name: str):
    data = bytearray(hex_path.read_bytes())
    efe_raw = data[efe_offset:efe_offset + UDF_SECTOR_SIZE]
    L_EA = struct.unpack('<I', efe_raw[208:212])[0]
    L_AD = struct.unpack('<I', efe_raw[212:216])[0]

    ad_base = 216 + L_EA
    ad_end = ad_base + L_AD
    fid_field = efe_raw[ad_base:ad_end]

    # ==================================================
    # 按照 ECMA-167  定义的 FID 结构
    # RBP     | 长度  | 字段名
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

    offset = 0
    embedded_fids = []
    while offset < len(fid_field):
        if len(fid_field) - offset < 38:
            print(f"FID文件损坏！剩余字节少于定义最短字节")
            break
        # 读取FID固定头计算总长度
        fid_fixed = fid_field[offset:offset + 38]
        L_FI = struct.unpack('<B', fid_fixed[19:20])[0]
        L_IU = struct.unpack('<H', fid_fixed[36:38])[0]

        # 计算FID总长度（含4字节对齐填充，严格遵循UDF标准）
        raw_len = 38 + L_FI + L_IU
        padding_len = 4 * ((raw_len + 3) // 4) - raw_len
        fid_total_len = raw_len + padding_len

        if offset + fid_total_len > len(fid_field):
            break

        # 提取完整FID原始数据（仅保留bytes）
        fid_raw = fid_field[offset:offset + fid_total_len]
        abs_fid_off = efe_offset + ad_base + offset  # 计算绝对地址
        embedded_fids.append((abs_fid_off, fid_raw))  # 存元组
        offset += fid_total_len

    if embedded_fids:
        for i, (fid_off, fid_data) in enumerate(embedded_fids):

            L_FI = fid_data[19]
            L_IU = struct.unpack('<H', fid_data[36:38])[0]
            icb_data = fid_data[20:36]
            file_info = long_ad_to_str(icb_data)

            # 目录项角色判定
            file_char = struct.unpack('<B', fid_data[18:19])[0]
            dir_bit = (file_char >> 1) & 0x01  # Bit 1: Directory
            parent_bit = (file_char >> 3) & 0x01  # Bit 3: Parent
            # 子项名解析

            if L_FI > 0 and len(fid_data) >= 38 + L_IU + L_FI:
                file_identifier = fid_data[38 + L_IU:38 + L_IU + L_FI]
                try:
                    file_name = dstring_to_str(file_identifier)
                except:
                    file_name = f"[十六进制] {file_identifier.hex(' ')}"
            elif parent_bit == 1:
                file_name = ".."  # 父目录固定文件名
            elif dir_bit == 1 and L_FI == 0:
                file_name = "."  # 当前目录固定文件名

            if parent_bit == 1:
                role = "父目录 (..)"
            elif dir_bit == 1 and L_FI == 0:
                role = "当前目录 (.)"
            elif dir_bit == 1:
                role = "子目录"
            else:
                role = "子文件"

            print(f"\n  FID #{i}:")
            print(f"    ICB: {file_info} ")
            print(f"    目录项角色: {role} ")
            print(f"    文件名: {file_name}")
    else:
        print("  未发现内嵌FID (AD Type != 3 或 L_AD=0)")

    try:
        choice_str = input("请输入要修改的FID序号 (0 到 {}): ".format(len(embedded_fids) - 1))
        choice = int(choice_str)
        if choice < 0 or choice >= len(embedded_fids):
            print("无效序号")
            return
    except ValueError:
        print("输入无效")
        return

    # ==================================================
    # 3. 准备修改
    # ==================================================

    target_abs_off, old_fid = embedded_fids[choice]
    old_len = len(old_fid)
    old_L_FI = old_fid[19]

    target_file_char = old_fid[18]
    target_dir_bit = (target_file_char >> 1) & 0x01
    target_parent_bit = (target_file_char >> 3) & 0x01

    if target_parent_bit == 1:
        print(f"父目录 (..) 不可修改！")
        return
    if target_dir_bit == 1 and old_L_FI == 0:
        print(f"当前目录 (.) 不可修改！")
        return

    old_L_IU = struct.unpack('<H', old_fid[36:38])[0]

    new_name_bytes = get_udf_filename(new_name)

    new_L_FI = len(new_name_bytes)

    if new_L_FI < 1 or new_L_FI > 255:
        raise ValueError(f"文件名长度 {new_L_FI} 非法")

    # 计算新长度
    new_len = 38 + old_L_IU + new_L_FI
    new_padding_len = 4 * ((new_len + 3) // 4) - new_len
    new_total_len = new_len + new_padding_len
    delta = new_total_len - old_len

    # ==================================================
    # 4. 插入逻辑 (移动后续数据)
    # ==================================================
    if delta != 0:
        # 确定需要移动的数据块边界
        old_fid_end = target_abs_off + old_len
        if delta > 0:
            data.extend(b'\x00' * delta)

            print(f"  正在移动后续数据 (从 0x{old_fid_end:X} 向后移动 {delta:+d} 字节)...")

            # data[new_start : new_end] = data[old_start : old_end]
            data[old_fid_end + delta: old_fid_end + delta + (len(data) - old_fid_end)] = data[old_fid_end: len(data)]
            print(f"  数据后移完成。")
        elif delta < 0:
            new_fid_end = target_abs_off + new_total_len

            print(f"  正在移动后续数据 (从 0x{old_fid_end:X} 向前移动 {delta:+d} 字节)...")
            data[new_fid_end: new_fid_end + (len(data) - old_fid_end)] = data[old_fid_end: len(data)]
            print(f"  数据前移完成。")

    # ==================================================
    # 5. 构建并写入新 FID
    # ==================================================
    new_fid = bytearray(new_total_len)
    new_fid[0:38] = old_fid[0:38]
    new_fid[19] = new_L_FI
    name_field = 38 + old_L_IU
    struct.pack_into('<H', new_fid, 10, (new_total_len - 16))
    new_fid[name_field: name_field + new_L_FI] = new_name_bytes
    new_fid[name_field + new_L_FI:] = b'\x00' * new_padding_len
    # 写入新 FID 到目标位置
    data[target_abs_off: target_abs_off + new_total_len] = new_fid

    # ==================================================
    # 6. 更新EFE
    # ==================================================

    new_L_AD = L_AD + delta
    # 1 更新 Length of Allocation Descriptors (=L_AD) (偏移 212)
    struct.pack_into('<I', data, efe_offset + 212, new_L_AD)

    efe_crc_length = 216 + new_L_AD + L_EA - 16
    struct.pack_into('<H', data, efe_offset + 10, efe_crc_length)

    new_info_length = L_EA + new_L_AD
    # 2 更新 Information Length (偏移 56)
    struct.pack_into('<Q', data, efe_offset + 56, new_info_length)
    # 3 更新 Object Size (偏移 64)
    struct.pack_into('<Q', data, efe_offset + 64, new_info_length)
    # ==================================================
    # 7. 写回文件
    # ==================================================
    hex_path.write_bytes(data)


if __name__ == '__main__':
    if len(sys.argv) != 4:
        print("用法: python py-renamefile.py  <镜像>  <EFE偏移>  <新名字>")
        sys.exit(1)
    rename_embedded_fid(Path(sys.argv[1]), int(sys.argv[2], 0), sys.argv[3])