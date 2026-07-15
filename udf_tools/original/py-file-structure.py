#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
UDF Descriptor Dumper
"""
import struct, sys
from typing import List, Dict
from wcwidth import wcswidth
from datetime import datetime, timedelta


#全局扇区大小变量定义
UDF_SECTOR_SIZE = 512


# ---------- 小工具 ----------
def dstring_to_str(b: bytes) -> str:
    """UDF dstring 格式解析（ASCII，尾部补0）"""
    try:
        return b.decode('ascii').split('\x00')[0]
    except UnicodeDecodeError:
        return "<decode error>"


def charspec_to_str(b: bytes) -> str:
    """UDF 64字节 charspec 解析 （1字节类型 ＋ 63字节内容）"""
    if len(b) != 64:
        return f"无效charspec（长度={len(b)}，标准要求64字节）"
    CharacterSetInformation = dstring_to_str(b[1:64])
    return f"{CharacterSetInformation}"


def regid_to_str(b: bytes) -> str:
    """UDF regid 32 字节的regid数据 """
    if len(b) != 32:
        return f"无效regid（长度={len(b)}，标准要求32字节）"

    flags = struct.unpack('<B', b[0:1])[0]
    dirty = (flags & 0x01) != 0
    protected = (flags & 0x02) != 0
    reserved_ok = (flags & 0xFC) == 0  # bit2-7必须为0

    flags_desc = []
    if dirty:
        flags_desc.append("Dirty（修改位标识）")
    else:
        flags_desc.append("Clean（有效标识）")
    if protected:
        flags_desc.append("Protected（保护位修改）")
    else:
        flags_desc.append("Unprotected（可修改）")
    if not reserved_ok:
        flags_desc.append("⚠ 保留位（bit2-7）非0（非标准）")

    # 3. 解析Identifier（RBP 1，23字节）
    identifier = dstring_to_str(b[1:24])
    if all(byte == 0x00 for byte in identifier):
        identifier_desc = "未指定标识符（全0）"
    else:
        first_byte = identifier[0]
        if first_byte == 0x2B:
            identifier_desc = f"ECMA-168/本标准定义标识符: {identifier}"
        elif first_byte == 0x2D:
            identifier_desc = f"未注册标识符: {identifier}"
        else:
            identifier_desc = f"ISO/IEC 13800注册标识符: {identifier}"

    return (
        f"  Flags: {', '.join(flags_desc)}\n"
        f"  Identifier: {identifier_desc}\n"
    )


def lb_addr_to_str(b: bytes) -> str:
    """UDF 6字节 lb_addr 解析（4字节逻辑块号 + 2字节分区引用）"""
    if len(b) != 6:
        return f"无效lb_addr（长度={len(b)}，标准要求6字节）"
    LogicalBlockNumber = struct.unpack('<I', b[0:4])[0]
    PartitionReferenceNumber = struct.unpack('<H', b[4:6])[0]
    return f"分区={PartitionReferenceNumber}, 逻辑块={LogicalBlockNumber}"


def extent_ad_to_str(b: bytes) -> str:
    """UDF 8字节 extent_ad 解析（Length+Location）"""
    if len(b) != 8:
        return f"无效扩展描述符（长度={len(b)}，标准要求8字节）"
    length = struct.unpack('<I', b[0:4])[0]
    location = struct.unpack('<I', b[4:8])[0]
    return f"起始扇区={location}, 长度={length}字节"


def short_ad_to_str(b: bytes) -> str:
    if len(b) != 8:
        return f"无效短分配描述符（长度={len(b)}，标准要求8字节）"
    length = struct.unpack('<I', b[0:4])[0]
    position = struct.unpack('<I', b[4:8])[0]
    return f"位置={position}, 长度={length}字节"


def long_ad_to_str(b: bytes) -> str:
    if len(b) != 16:
        return f"无效长分配描述符（长度={len(b)}，标准要求16字节）"
    length = struct.unpack('<I', b[0:4])[0]
    position = lb_addr_to_str(b[4:10])
    ImplementationUse = b[10:16].hex()
    return f"长度={length}字节, 地址=[{position}], 实现使用={ImplementationUse}"


def icbtag_to_str(b: bytes) -> str:
    """20字节 ICB Tag 解析"""
    if len(b) != 20:
        return f"无效ICB Tag（长度={len(b)}，标准要求20字节）"

    PriorRecordedNumberofDirectEntries = struct.unpack('<I', b[0:4])[0]
    StrategyType = struct.unpack('<H', b[4:6])[0]
    StrategyParameter = b[6:8]
    MaximumNumberofEntries = struct.unpack('<H', b[8:10])[0]
    Reserved = b[10]
    FileType = b[11]
    ParentICBLocation = b[12:18]  # 6字节 lb_addr
    Flags = struct.unpack('<H', b[18:20])[0]
    strategy_map = {
        0: "未指定",
        1: "策略在4/A.2中定义",
        2: "策略在4/A.3中定义",
        3: "策略在4/A.4中定义",
        4: "策略在4/A.5中定义",
    }
    if 5 <= StrategyType <= 4095:
        strategy_desc = "保留（5-4095）"
    elif 4096 <= StrategyType <= 65535:
        strategy_desc = "需与介质收发方协商"
    else:
        strategy_desc = strategy_map.get(StrategyType, f"未知策略({StrategyType})")
    file_type_map = {
        0: "未指定",
        1: "未分配空间条目",
        2: "分区完整性条目",
        3: "间接条目",
        4: "目录",
        5: "字节序列/随机访问文件",
        6: "块特殊设备文件",
        7: "字符特殊设备文件",
        8: "扩展属性记录",
        9: "FIFO文件",
        10: "套接字文件",
        11: "终端条目",
        12: "符号链接",
        13: "流目录",
    }
    if 14 <= FileType <= 247:
        file_type_desc = "保留（14-247）"
    elif 248 <= FileType <= 255:
        file_type_desc = "需与介质收发方协商"
    else:
        file_type_desc = file_type_map.get(FileType, f"未知文件类型({FileType})")

    flag_bits = []
    ad_type = Flags & 0x07
    ad_type_map = {
        0: "短分配描述符",
        1: "长分配描述符",
        2: "扩展分配描述符",
        3: "单分配描述符",
    }
    flag_bits.append(f"分配类型={ad_type_map.get(ad_type, f'保留({ad_type})')}")
    if FileType == 4:  # 仅目录有效
        if Flags & 0x08:
            flag_bits.append("目录需按4/8.6.1排序")
        else:
            flag_bits.append("目录无需排序")
    if Flags & 0x10:
        flag_bits.append("不可重定位（分配描述符不可修改）")
    else:
        flag_bits.append("可重定位")
    if Flags & 0x20:
        flag_bits.append("已归档（创建/写入后设置）")
    if Flags & 0x40:
        flag_bits.append("Setuid（ISO/IEC 9945-1）")
    if Flags & 0x80:
        flag_bits.append("Setgid（ISO/IEC 9945-1）")
    if Flags & 0x100:
        flag_bits.append("Sticky（ISO/IEC 9945-1）")
    if Flags & 0x200:
        flag_bits.append("连续（每个extent必须从下一个逻辑块开始）")
    else:
        flag_bits.append("非连续")
    if Flags & 0x800:
        flag_bits.append("数据已转换（非标准转换）")
    else:
        flag_bits.append("数据未转换")
    if FileType == 4:
        if Flags & 0x1000:
            flag_bits.append("支持多版本（目录可含同名文件标识）")
        else:
            flag_bits.append("不支持多版本")
    if Flags & 0x2000:
        flag_bits.append("流文件（由流目录标识）")
    else:
        flag_bits.append("非流文件")
    parent_icb_str = lb_addr_to_str(ParentICBLocation)
    reserved_ok = "（符合标准）" if Reserved == 0 else f"（非标准值0x{Reserved:02X}）"

    return (
        f"目录项数={PriorRecordedNumberofDirectEntries}, "
        f"策略={StrategyType}({strategy_desc}), "
        f"最大条目数={MaximumNumberofEntries}, "
        f"保留=0x{Reserved:02X}{reserved_ok}, "
        f"文件类型={FileType}({file_type_desc}), "
        f"父ICB=[{parent_icb_str}], "
        f"Flag=0x{Flags:04X}({', '.join(flag_bits)})\n"
    )


def udf_timestamp_to_datetime(data: bytes) -> datetime:
    """
    转换UDF时间戳（12字节）为北京时间格式
    遵循ECMA-167标准：
    - 字节0-1：Type and Time Zone（16位小端，高4位=Type，低12位=时区偏移（分钟，有符号））
    - 字节2-3：Year（16位无符号，1-9999）
    - 字节4：Month（1-12）
    - 字节5：Day（1-31）
    - 字节6：Hour（0-23）
    - 字节7：Minute（0-59）
    - 字节8：Second（0-59）
    - 字节9：Centiseconds（0-99，1/100秒）
    - 字节10：Hundreds of microseconds（0-99，100微秒单位）
    - 字节11：Microseconds（0-99，1微秒单位）
    """
    # 1. 基础校验：长度必须为12字节
    if len(data) != 12:
        return f"无效时间戳（长度={len(data)}，标准要求12字节）"
    # 2. 空时间戳判断：全0表示未指定
    if all(b == 0 for b in data):
        return "时间戳未指定"

    try:
        # ========== 第一步：解析Type and Time Zone（前2字节） ==========
        # 解包前2字节为小端16位无符号整数
        type_timezone = struct.unpack('<H', data[0:2])[0]
        # 拆分：最高4位=Type，低12位=时区偏移（分钟）
        ts_type = (type_timezone >> 12) & 0x0F  # 提取最高4位（Type）
        tz_offset_raw = type_timezone & 0x0FFF  # 提取低12位（原始时区偏移值）

        # 处理时区偏移：低12位是有符号整数（补码），范围-1440~1440分钟（-24~+24小时）
        # 特殊值：0xF801（-2047）表示无时区偏移，默认按UTC处理
        if tz_offset_raw == 0xF801:
            tz_offset_min = 0  # 无时区偏移 → UTC
        else:
            # 转换12位补码为有符号整数
            if tz_offset_raw & 0x0800:  # 最高位为1 → 负数
                tz_offset_min = tz_offset_raw - 0x1000
            else:
                tz_offset_min = tz_offset_raw

        # ========== 第二步：解析时间字段 ==========
        year = struct.unpack('<h', data[2:4])[0]
        month = data[4]
        day = data[5]
        hour = data[6]
        minute = data[7]
        second = data[8]
        centiseconds = data[9]
        hundreds_micro = data[10]
        micro = data[11]

        # ========== 第三步：校验字段有效性 ==========
        if (year < 1 or year > 9999
                or month < 1 or month > 12
                or day < 1 or day > 31
                or hour < 0 or hour > 23
                or minute < 0 or minute > 59
                or second < 0 or second > 59
                or centiseconds < 0 or centiseconds > 99
                or hundreds_micro < 0 or hundreds_micro > 99
                or micro < 0 or micro > 99):
            return "无效时间（字段值超出范围）"

        total_micro = centiseconds * 10000 + hundreds_micro * 100 + micro

        # ========== 第四步：时区转换为北京时间（UTC+8） ==========
        # 1. 构造原始时间对象（带原始时区）
        try:
            raw_dt = datetime(year, month, day, hour, minute, second, total_micro)
        except ValueError as e:
            return f"无效时间（日期逻辑错误）: {str(e)}"

        # 2. 计算原始时间的UTC时间
        # - Type=0：原始时间是UTC → UTC时间=原始时间
        # - Type=1：原始时间是本地时间 → UTC时间=原始时间 - 时区偏移
        if ts_type == 0:  # Type=0 → 原始时间=UTC
            utc_dt = raw_dt
        elif ts_type == 1:  # Type=1 → 原始时间=本地时间 → 转UTC
            utc_dt = raw_dt - timedelta(minutes=tz_offset_min)
        else:  # Type=2-15：保留值，默认按UTC处理
            utc_dt = raw_dt

        # 3. 转换为北京时间（UTC+8小时）
        beijing_tz = timedelta(hours=8)
        beijing_dt = utc_dt + beijing_tz

        # ========== 第五步：格式化输出 ==========
        # 输出格式：YYYY-MM-DD HH:MM:SS.ffffff
        return beijing_dt.strftime("%Y-%m-%d %H:%M:%S.%f")

    except struct.error as e:
        return f"解包失败: {str(e)}"
    except Exception as e:
        return f"转换失败: {str(e)}"


def textpad(text, width):
    """文本填充逻辑"""
    return text + ' ' * (width - wcswidth(text))

def embedded_FID_to_str(fid_data: bytes, base_off: int = 0) -> str:
    if len(fid_data) < 38:
        return "[FID] 数据不足（<38字节，无法解析固定头）"
    # Descriptor Tag (RBP 0, 16字节)
    tag_id = struct.unpack('<H', fid_data[0:2])[0]
    tag_version = struct.unpack('<H', fid_data[2:4])[0]
    tag_checksum = struct.unpack('<B', fid_data[4:5])[0]
    tag_loc = struct.unpack('<I', fid_data[12:16])[0]
    file_ver = struct.unpack('<H', fid_data[16:18])[0]
    file_char = struct.unpack('<B', fid_data[18:19])[0]
    exist_bit = (file_char >> 0) & 0x01    # Bit 0: Existence
    dir_bit = (file_char >> 1) & 0x01     # Bit 1: Directory
    delete_bit = (file_char >> 2) & 0x01  # Bit 2: Deleted
    parent_bit = (file_char >> 3) & 0x01  # Bit 3: Parent
    meta_bit = (file_char >> 4) & 0x01   # Bit 4: Metadata
    reserved_char = file_char >> 5        # Bits 5-7: Reserved

    # Length of File Identifier (L_FI, RBP 19, 1字节)
    L_FI = struct.unpack('<B', fid_data[19:20])[0]
    # Parent bit为1时，L_FI必须为0
    if parent_bit == 1 and L_FI != 0:
        fi_warn = " ⚠️ 标准违规：Parent bit=1时L_FI必须为0"
    else:
        fi_warn = ""

    # ICB (RBP 20, 16字节，long_ad)
    icb_data = fid_data[20:36]
    fi_icb = long_ad_to_str(icb_data)
    L_IU = struct.unpack('<H', fid_data[36:38])[0]
    impl_use = fid_data[38:38+L_IU].hex(' ') if L_IU > 0 else "无"
    fi_start = 38 + L_IU
    file_name = ""
    if L_FI > 0 and len(fid_data) >= fi_start + L_FI:
        fname_bytes = fid_data[fi_start:fi_start+L_FI]
        try:
            file_name = dstring_to_str(fname_bytes)
        except:
            file_name = f"[十六进制] {fname_bytes.hex(' ')}"
    elif parent_bit == 1:
        file_name = ".."  # 父目录固定文件名
    elif dir_bit == 1 and L_FI == 0:
        file_name = "."   # 当前目录固定文件名

    raw_len = 38 + L_FI + L_IU
    padding_len = 4 * ((raw_len + 3) // 4) - raw_len
    padding_start = fi_start + L_FI
    padding_data = fid_data[padding_start:padding_start+padding_len] if padding_len > 0 else b""
    padding_all_zero = all(b == 0x00 for b in padding_data)

    if parent_bit == 1:
        role = "父目录 (..)"
    elif dir_bit == 1 and L_FI == 0:
        role = "当前目录 (.)"
    elif dir_bit == 1:
        role = "子目录"
    else:
        role = "子文件"

    return f"""
[FID 偏移: 0x{base_off:08X}]
├─ Descriptor Tag: ID=0x{tag_id:04X}, Ver={tag_version}, Checksum=0x{tag_checksum:02X}, Loc={tag_loc}
├─ File Version: {file_ver}
├─ File Characteristics:
│  ├─ Existence: {'隐藏' if exist_bit else '可见'}
│  ├─ Directory: {'是' if dir_bit else '否'}
│  ├─ Deleted: {'已删除' if delete_bit else '未删除'}
│  ├─ Parent: {'是' if parent_bit else '否'}
│  ├─ Metadata: {'是' if meta_bit else '否'}
│  └─ Reserved Bits: 0x{reserved_char:02X} (应为00)
├─ 目录项角色: {role}
├─ Length of File Identifier: {L_FI} 字节{fi_warn}
├─ Length of Implementation Use: {L_IU} 字节
├─ ICB:{fi_icb}
├─ Implementation Use: {impl_use}
├─ File Name: {file_name}
└─ Padding: {padding_len} 字节, 全0x00: {'✅' if padding_all_zero else '❌ 非标准值'}
""".strip()


# ---------- 解析器 ----------
def parse_terminating_descriptor(entry: bytes, base_off: int) -> List[Dict]:
    """Type8 Terminating Descriptor（终止描述符）"""
    fields = [
        ("TagIdentifier", 0, 2, "描述符类型（固定为8）"),
        ("DescriptorVersion", 2, 2, "描述符版本"),
        ("TagChecksum", 4, 1, "Tag校验和"),
        ("TagReserved", 5, 1, "保留字段（#00 byte）"),
        ("TagSerialNumber", 6, 2, "Tag序列号"),
        ("DescriptorCRC", 8, 2, "描述符CRC校验值"),
        ("DescriptorCRCLength", 10, 2, "CRC覆盖字节长度"),
        ("TagLocation", 12, 4, "Tag位置（逻辑块号）"),
        ("Reserved", 16, UDF_SECTOR_SIZE - 16, "保留字段（全#00）"),
    ]
    info = []
    for name, offset, size, desc in fields:
        raw = entry[offset: offset + size]
        # 按标准解包，适配不同长度字段
        if name == "TagIdentifier":
            val = struct.unpack('<H', raw)[0]
            value = f"0x{val:04X}（标准要求固定为8）"
        elif name == "TagReserved":
            val = struct.unpack('<B', raw)[0]
            value = f"0x{val:02X}（标准要求为#00）" if val == 0 else f"0x{val:02X}（非标准值）"
        elif name == "TagLocation":
            val = struct.unpack('<I', raw)[0]
            value = val
        elif size == 4:
            val = struct.unpack('<I', raw)[0]
            value = f"0x{val:08X}"
        elif size == 2:
            val = struct.unpack('<H', raw)[0]
            value = f"0x{val:04X}"
        elif size == 1:
            val = struct.unpack('<B', raw)[0]
            value = f"0x{val:02X}"
        else:  # 496字节保留字段，简化显示
            is_all_zero = all(b == 0 for b in raw)
            value = "全0（符合标准）" if is_all_zero else f"非标准值（前16字节：{raw[:16].hex(' ')}...）"
        # 原始值显示：长字段截断，短字段完整
        raw_hex = raw[:16].hex(' ') + ("..." if size > 16 else "")
        info.append(dict(
            offset=base_off + offset,
            field=name,
            meaning=desc,
            raw=raw_hex,
            value=value
        ))
    return info


def parse_file_set_descriptor(entry: bytes, base_off: int) -> List[Dict]:
    """Type256 File Set Descriptor（文件集描述符）"""
    fields = [
        ("TagIdentifier", 0, 2, "描述符类型（固定为256）"),
        ("DescriptorVersion", 2, 2, "描述符版本"),
        ("TagChecksum", 4, 1, "Tag校验和"),
        ("TagReserved", 5, 1, "保留字段（#00 byte）"),
        ("TagSerialNumber", 6, 2, "Tag序列号"),
        ("DescriptorCRC", 8, 2, "描述符CRC校验值"),
        ("DescriptorCRCLength", 10, 2, "CRC覆盖字节长度"),
        ("TagLocation", 12, 4, "Tag位置（逻辑块号）"),
        ("RecordingDateandTime", 16, 12, "描述符记录时间"),
        ("InterchangeLevel", 28, 2, "介质交换级别"),
        ("MaximumInterchangeLevel", 30, 2, "最大介质交换级别"),
        ("CharacterSetList", 32, 4, "字符集列表标识"),
        ("MaximumCharacterSetList", 36, 4, "最大字符集列表标识"),
        ("FileSetNumber", 40, 4, "文件集编号"),
        ("FileSetDescriptorNumber", 44, 4, "文件集描述符编号"),
        ("LogicalVolumeIdentifierCharacterSet", 48, 64, "逻辑卷标识字符集"),
        ("LogicalVolumeIdentifier", 112, 128, "逻辑卷标识"),
        ("FileSetCharacterSet", 240, 64, "文件集字符集"),
        ("FileSetIdentifier", 304, 32, "文件集标识"),
        ("CopyrightFileIdentifier", 336, 32, "版权文件标识"),
        ("AbstractFileIdentifier", 368, 32, "摘要文件标识"),
        ("RootDirectoryICB", 400, 16, "根目录ICB"),
        ("DomainIdentifier", 416, 32, "域标识"),
        ("NextExtent", 448, 16, "下一个扩展"),
        ("SystemStreamDirectoryICB", 464, 16, "系统流目录ICB"),
        ("Reserved", 480, 32, "保留字段（全#00）"),
    ]

    info = []
    for name, offset, size, desc in fields:
        raw = entry[offset: offset + size]
        # 按标准类型解析
        if name == "TagIdentifier":
            val = struct.unpack('<H', raw)[0]
            value = f"0x{val:04X}（标准要求固定为256）"
        elif name == "TagReserved":
            val = struct.unpack('<B', raw)[0]
            value = f"0x{val:02X}（标准要求为#00）" if val == 0 else f"0x{val:02X}（非标准值）"
        elif name == "TagLocation":
            val = struct.unpack('<I', raw)[0]
            value = val
        elif name == "RecordingDateandTime":
            value = udf_timestamp_to_datetime(raw)
            #Uint16
        elif name in ("InterchangeLevel", "MaximumInterchangeLevel"):
            val = struct.unpack('<H', raw)[0]
            value = f"{val}"
            #Uint32
        elif name in ("CharacterSetList", "MaximumCharacterSetList",
                      "FileSetNumber", "FileSetDescriptorNumber"):
            val = struct.unpack('<I', raw)[0]
            value = f"0x{val:08X}"
        elif name.endswith("Identifier") and name != "DomainIdentifier":
            # dstring 类型
            value = dstring_to_str(raw)
        elif name in ("RootDirectoryICB", "NextExtent", "SystemStreamDirectoryICB"):
            # long_ad 类型（16字节）
            value = long_ad_to_str(raw)
        elif name == "DomainIdentifier":
            # regid 类型（32字节）
            value = regid_to_str(raw)
        elif name == "Reserved":
            is_all_zero = all(b == 0 for b in raw)
            value = "全0（符合标准）" if is_all_zero else f"非标准值：{raw.hex(' ')}"
        elif size == 4:
            val = struct.unpack('<I', raw)[0]
            value = f"0x{val:08X}"
        elif size == 2:
            val = struct.unpack('<H', raw)[0]
            value = f"0x{val:04X}"
        elif size == 1:
            val = struct.unpack('<B', raw)[0]
            value = f"0x{val:02X}"
        else:
            # charspec 类型（64字节），按字节显示
            value = charspec_to_str(raw)
        # 原始值显示：长字段截断
        raw_hex = raw[:16].hex(' ') + ("..." if size > 16 else "")
        info.append(dict(
            offset=base_off + offset,
            field=name,
            meaning=desc,
            raw=raw_hex,
            value=value
        ))
    return info


def parse_file_identifier_descriptor(entry: bytes, base_off: int) -> List[Dict]:
    """Type257 File Identifier Descriptor（文件标识描述符）"""
    # 先读取动态长度字段（L_FI 和 L_IU），用于计算后续字段偏移
    L_FI = struct.unpack('<B', entry[19:20])[0] if len(entry) >= 20 else 0
    L_IU = struct.unpack('<H', entry[36:38])[0] if len(entry) >= 38 else 0
    fields = [
        ("TagIdentifier", 0, 2, "描述符类型（固定为257）"),
        ("DescriptorVersion", 2, 2, "描述符版本"),
        ("TagChecksum", 4, 1, "Tag校验和"),
        ("TagReserved", 5, 1, "保留字段（#00 byte）"),
        ("TagSerialNumber", 6, 2, "Tag序列号"),
        ("DescriptorCRC", 8, 2, "描述符CRC校验值"),
        ("DescriptorCRCLength", 10, 2, "CRC覆盖字节长度"),
        ("TagLocation", 12, 4, "Tag位置（逻辑块号）"),
        ("FileVersionNumber", 16, 2, "文件版本号"),
        ("FileCharacteristics", 18, 1, "文件特征位"),
        ("LengthOfFileIdentifier", 19, 1, f"文件标识长度 L_FI = {L_FI} 字节"),
        ("ICB", 20, 16, "ICB地址"),
        ("LengthOfImplementationUse", 36, 2, f"实现使用长度 L_IU = {L_IU} 字节"),
        # 动态字段（依赖 L_IU 和 L_FI）
        ("ImplementationUse", 38, L_IU, f"实现使用数据（若L_IU>0）"),
        ("FileIdentifier", 38 + L_IU, L_FI, f"文件标识（{L_FI}字节）"),
        ("Padding", 38 + L_IU + L_FI, len(entry) - (38 + L_IU + L_FI), "填充字节（对齐扇区）"),
    ]

    info = []
    for name, offset, size, desc in fields:
        if offset + size > len(entry):
            # 字段超出数据范围，标记为无效
            info.append(dict(
                offset=base_off + offset,
                field=name,
                meaning=desc,
                raw="",
                value="字段超出数据范围（无效）"
            ))
            continue

        raw = entry[offset: offset + size]
        if name == "TagIdentifier":
            val = struct.unpack('<H', raw)[0]
            value = f"0x{val:04X}（标准要求固定为257）"
        elif name == "TagReserved":
            val = struct.unpack('<B', raw)[0]
            value = f"0x{val:02X}（标准要求为#00）" if val == 0 else f"0x{val:02X}（非标准值）"
        elif name == "TagLocation":
            val = struct.unpack('<I', raw)[0]
            value = val
        elif name == "FileVersionNumber":
            val = struct.unpack('<H', raw)[0]
            if 1 <= val <= 32767:
                value = f"{val}（有效版本号）"
            else:
                value = f"{val}（保留值）"
        elif name == "FileCharacteristics":
            val = struct.unpack('<B', raw)[0]
            bits = {
                "Existence": "不可见" if (val & 0x01) else "可见",
                "Directory": "目录" if (val & 0x02) else "文件",
                "Deleted": "已删除" if (val & 0x04) else "未删除",
                "Parent": "父目录ICB" if (val & 0x08) else "自身ICB",
                "Metadata": "实现数据" if (val & 0x10) else "用户数据",
            }
            value = f"0x{val:02X}（{', '.join([f'{k}={v}' for k, v in bits.items()])}）"
        elif name == "ICB":
            value = long_ad_to_str(raw)
        elif name == "ImplementationUse":
            if L_IU > 0:
                regid_raw = raw[:32] if len(raw) >= 32 else raw
                value = f"regid: {regid_raw.hex(' ')}（剩余{len(raw) - 32}字节实现数据）"
            else:
                value = "无实现使用数据"
        elif name == "FileIdentifier":
            value = dstring_to_str(raw)
        elif name == "Padding":
            is_all_zero = all(b == 0 for b in raw)
            value = "全0（符合标准）" if is_all_zero else f"非标准填充：{raw.hex(' ')}"
        elif size == 4:
            val = struct.unpack('<I', raw)[0]
            value = f"0x{val:08X}"
        elif size == 2:
            val = struct.unpack('<H', raw)[0]
            value = f"0x{val:04X}"
        elif size == 1:
            val = struct.unpack('<B', raw)[0]
            value = f"0x{val:02X}"
        else:
            value = raw[:16].hex(' ') + ("..." if size > 16 else "")

        # 原始值显示：长字段截断
        raw_hex = raw[:16].hex(' ') + ("..." if size > 16 else "")
        info.append(dict(
            offset=base_off + offset,
            field=name,
            meaning=desc,
            raw=raw_hex,
            value=value
        ))
    return info


def parse_allocation_extent_descriptor(entry: bytes, base_off: int) -> List[Dict]:
    """Type258 Allocation Extent Descriptor（分配扩展描述符）"""
    fields = [
        # 16字节 Descriptor Tag（Tag=258，按图2严格定义）
        ("TagIdentifier", 0, 2, "描述符类型（固定为258）"),
        ("DescriptorVersion", 2, 2, "描述符版本"),
        ("TagChecksum", 4, 1, "Tag校验和"),
        ("TagReserved", 5, 1, "保留字段（#00 byte）"),
        ("TagSerialNumber", 6, 2, "Tag序列号"),
        ("DescriptorCRC", 8, 2, "描述符CRC校验值"),
        ("DescriptorCRCLength", 10, 2, "CRC覆盖字节长度"),
        ("TagLocation", 12, 4, "Tag位置（逻辑块号）"),
        ("PreviousAllocationExtentLocation", 16, 4, "前序分配扩展位置（0表示无）"),
        ("LengthofAllocationDescriptors", 20, 4, "后续分配描述符总长度 L_AD（字节）"),
        ("Reserved", 24, UDF_SECTOR_SIZE - 24, "保留字段（全#00）"),
    ]

    info = []
    for name, offset, size, desc in fields:
        if offset + size > len(entry):
            info.append(dict(
                offset=base_off + offset,
                field=name,
                meaning=desc,
                raw="",
                value="字段超出数据范围（无效）"
            ))
            continue

        raw = entry[offset: offset + size]
        if name == "TagIdentifier":
            val = struct.unpack('<H', raw)[0]
            value = f"0x{val:04X}（标准要求固定为258）"
        elif name == "TagReserved":
            val = struct.unpack('<B', raw)[0]
            value = f"0x{val:02X}（标准要求为#00）" if val == 0 else f"0x{val:02X}（非标准值）"
        elif name == "TagLocation":
            val = struct.unpack('<I', raw)[0]
            value = val
        elif name == "PreviousAllocationExtentLocation":
            val = struct.unpack('<I', raw)[0]
            value = f"{val}（逻辑块号）" if val != 0 else "0（无前置分配扩展）"
        elif name == "LengthofAllocationDescriptors":
            val = struct.unpack('<I', raw)[0]
            value = f"{val} 字节（后续分配描述符总长度 L_AD）"
        elif name == "Reserved":
            is_all_zero = all(b == 0 for b in raw)
            value = "全0（符合标准）" if is_all_zero else f"非标准值（前16字节：{raw[:16].hex(' ')}...）"
        elif size == 4:
            val = struct.unpack('<I', raw)[0]
            value = f"0x{val:08X}"
        elif size == 2:
            val = struct.unpack('<H', raw)[0]
            value = f"0x{val:04X}"
        elif size == 1:
            val = struct.unpack('<B', raw)[0]
            value = f"0x{val:02X}"
        else:
            value = raw[:16].hex(' ') + ("..." if size > 16 else "")
        # 原始值显示：长字段截断，保持输出统一
        raw_hex = raw[:16].hex(' ') + ("..." if size > 16 else "")
        info.append(dict(
            offset=base_off + offset,
            field=name,
            meaning=desc,
            raw=raw_hex,
            value=value
        ))
    return info


def parse_indirect_entry(entry: bytes, base_off: int) -> List[Dict]:
    """Type259 Indirect Entry（间接条目）"""
    fields = [
        # 16字节 Descriptor Tag（Tag=259，标准定义）
        ("TagIdentifier", 0, 2, "描述符类型（固定为259）"),
        ("DescriptorVersion", 2, 2, "描述符版本"),
        ("TagChecksum", 4, 1, "Tag校验和"),
        ("TagReserved", 5, 1, "保留字段（#00 byte）"),
        ("TagSerialNumber", 6, 2, "Tag序列号"),
        ("DescriptorCRC", 8, 2, "描述符CRC校验值"),
        ("DescriptorCRCLength", 10, 2, "CRC覆盖字节长度"),
        ("TagLocation", 12, 4, "Tag位置（逻辑块号）"),
        ("ICBTag", 16, 20, "ICB Tag（文件类型固定为3=间接条目）"),
        ("IndirectICB", 36, 16, "Indirect ICB（long_ad类型，指向实际ICB）"),
    ]

    info = []
    for name, offset, size, desc in fields:
        if offset + size > len(entry):
            info.append(dict(
                offset=base_off + offset,
                field=name,
                meaning=desc,
                raw="",
                value="字段超出数据范围（无效）"
            ))
            continue

        raw = entry[offset: offset + size]
        if name == "TagIdentifier":
            val = struct.unpack('<H', raw)[0]
            value = f"0x{val:04X}（标准要求固定为259）"
        elif name == "TagReserved":
            val = struct.unpack('<B', raw)[0]
            value = f"0x{val:02X}（标准要求为#00）" if val == 0 else f"0x{val:02X}（非标准值）"
        elif name == "TagLocation":
            val = struct.unpack('<I', raw)[0]
            value = val  # 逻辑块号直接显示数值
        elif name == "ICBTag":
            icb_str = icbtag_to_str(raw)
            # ICB Tag的FileType在第11字节（0-based），对应ECMA-167 4/14.6.1
            file_type = raw[11] if len(raw) >= 12 else 0
            if file_type == 3:
                value = f"[符合标准] {icb_str}"
            else:
                value = f"[非标准！FileType={file_type}（应为3）] {icb_str}"
        elif name == "IndirectICB":
            # 若你已有long_ad_to_str函数，直接替换为：value = long_ad_to_str(raw)
            value = long_ad_to_str(raw)
        elif size == 4:
            val = struct.unpack('<I', raw)[0]
            value = f"0x{val:08X}"
        elif size == 2:
            val = struct.unpack('<H', raw)[0]
            value = f"0x{val:04X}"
        elif size == 1:
            val = struct.unpack('<B', raw)[0]
            value = f"0x{val:02X}"
        else:
            value = raw[:16].hex(' ') + ("..." if size > 16 else "")

        # 原始值统一截断为前16字节显示，保持输出整洁
        raw_hex = raw[:16].hex(' ') + ("..." if size > 16 else "")
        info.append(dict(
            offset=base_off + offset,
            field=name,
            meaning=desc,
            raw=raw_hex,
            value=value
        ))
    return info


def parse_terminal_entry(entry: bytes, base_off: int) -> List[Dict]:
    """Type260 Terminal Entry（终端条目）"""
    fields = [
        # 16字节 Descriptor Tag（Tag=260，按图2严格定义）
        ("TagIdentifier", 0, 2, "描述符类型（固定为260）"),
        ("DescriptorVersion", 2, 2, "描述符版本"),
        ("TagChecksum", 4, 1, "Tag校验和"),
        ("TagReserved", 5, 1, "保留字段（#00 byte）"),
        ("TagSerialNumber", 6, 2, "Tag序列号"),
        ("DescriptorCRC", 8, 2, "描述符CRC校验值"),
        ("DescriptorCRCLength", 10, 2, "CRC覆盖字节长度"),
        ("TagLocation", 12, 4, "Tag位置（逻辑块号）"),
        ("ICBTag", 16, 20, "ICB Tag（文件类型固定为11=终端条目）"),
        ("Reserved", 36, UDF_SECTOR_SIZE - 36, "保留字段（全#00）"),
    ]

    info = []
    for name, offset, size, desc in fields:
        if offset + size > len(entry):
            info.append(dict(
                offset=base_off + offset,
                field=name,
                meaning=desc,
                raw="",
                value="字段超出数据范围（无效）"
            ))
            continue

        raw = entry[offset: offset + size]
        if name == "TagIdentifier":
            val = struct.unpack('<H', raw)[0]
            value = f"0x{val:04X}（标准要求固定为260）"
        elif name == "TagReserved":
            val = struct.unpack('<B', raw)[0]
            value = f"0x{val:02X}（标准要求为#00）" if val == 0 else f"0x{val:02X}（非标准值）"
        elif name == "TagLocation":
            val = struct.unpack('<I', raw)[0]
            value = val
        elif name == "ICBTag":
            icb_str = icbtag_to_str(raw)
            file_type = raw[11] if len(raw) >= 12 else 0
            if file_type == 11:
                value = f"[符合标准] {icb_str}"
            else:
                value = f"[非标准！FileType={file_type}（应为11）] {icb_str}"
        elif name == "Reserved":
            is_all_zero = all(b == 0 for b in raw)
            value = "全0（符合标准）" if is_all_zero else f"非标准值（前16字节：{raw[:16].hex(' ')}...）"
        elif size == 4:
            val = struct.unpack('<I', raw)[0]
            value = f"0x{val:08X}"
        elif size == 2:
            val = struct.unpack('<H', raw)[0]
            value = f"0x{val:04X}"
        elif size == 1:
            val = struct.unpack('<B', raw)[0]
            value = f"0x{val:02X}"
        else:
            value = raw[:16].hex(' ') + ("..." if size > 16 else "")

        # 原始值显示：长字段截断，保持输出统一
        raw_hex = raw[:16].hex(' ') + ("..." if size > 16 else "")
        info.append(dict(
            offset=base_off + offset,
            field=name,
            meaning=desc,
            raw=raw_hex,
            value=value
        ))
    return info


def parse_file_entry(entry: bytes, base_off: int) -> List[Dict]:
    """Type261 File Entry（文件条目）"""
    L_EA = struct.unpack('<I', entry[168:172])[0] if len(entry) >= 172 else 0
    L_AD = struct.unpack('<I', entry[172:176])[0] if len(entry) >= 176 else 0
    fields = [
        ("TagIdentifier", 0, 2, "描述符类型（固定为261）"),
        ("DescriptorVersion", 2, 2, "描述符版本"),
        ("TagChecksum", 4, 1, "Tag校验和"),
        ("TagReserved", 5, 1, "保留字段（#00 byte）"),
        ("TagSerialNumber", 6, 2, "Tag序列号"),
        ("DescriptorCRC", 8, 2, "描述符CRC校验值"),
        ("DescriptorCRCLength", 10, 2, "CRC覆盖字节长度"),
        ("TagLocation", 12, 4, "Tag位置（逻辑块号）"),
        ("ICBTag", 16, 20, "ICB Tag"),
        ("Uid", 36, 4, "文件所有者用户ID"),
        ("Gid", 40, 4, "文件所有者组ID"),
        ("Permissions", 44, 4, "访问权限"),
        ("FileLinkCount", 48, 2, "文件链接数"),
        ("RecordFormat", 50, 1, "记录格式"),
        ("RecordDisplayAttributes", 51, 1, "记录显示属性"),
        ("RecordLength", 52, 4, "记录长度"),
        ("InformationLength", 56, 8, "文件信息长度（逻辑字节数）"),
        ("LogicalBlocksRecorded", 64, 8, "已记录逻辑块数（物理占用）"),
        ("AccessDateandTime", 72, 12, "访问时间"),
        ("ModificationDateandTime", 84, 12, "修改时间"),
        ("AttributeDateandTime", 96, 12, "属性修改时间"),
        ("Checkpoint", 108, 4, "检查点（Uint32）"),
        ("ExtendedAttributeICB", 112, 16, "扩展属性ICB"),
        ("ImplementationIdentifier", 128, 32, "实现者标识"),
        ("UniqueId", 160, 8, "文件唯一ID（Uint64）"),
        ("LengthofExtendedAttributes", 168, 4, f"扩展属性长度 L_EA = {L_EA} 字节"),
        ("LengthofAllocationDescriptors", 172, 4, f"分配描述符长度 L_AD = {L_AD} 字节"),
        # 动态字段（依赖 L_EA 和 L_AD）
        ("ExtendedAttributes", 176, L_EA, f"扩展属性数据（{L_EA}字节）"),
        ("AllocationDescriptors", 176 + L_EA, L_AD, f"分配描述符数据（{L_AD}字节）"),
    ]

    info = []
    for name, offset, size, desc in fields:
        if offset + size > len(entry):
            info.append(dict(
                offset=base_off + offset,
                field=name,
                meaning=desc,
                raw="",
                value="字段超出数据范围（无效）"
            ))
            continue

        raw = entry[offset: offset + size]
        if name == "TagIdentifier":
            val = struct.unpack('<H', raw)[0]
            value = f"0x{val:04X}（标准要求固定为261）"
        elif name == "TagReserved":
            val = struct.unpack('<B', raw)[0]
            value = f"0x{val:02X}（标准要求为#00）" if val == 0 else f"0x{val:02X}（非标准值）"
        elif name == "TagLocation":
            val = struct.unpack('<I', raw)[0]
            value = val
        elif name == "ICBTag":
            val =icbtag_to_str(raw)
            value = f"[ICB解析] {val}"
        elif name in ("AccessDateandTime", "ModificationDateandTime", "AttributeDateandTime"):
            value = udf_timestamp_to_datetime(raw)
        elif name == "Permissions":
            val = struct.unpack('<I', raw)[0]
            # 按图22解析权限位（Other: bits0-4, Group: bits5-9, Owner: bits10-14, 保留: bits15-31）
            perm_bits = []
            other_exec = (val & 0x01) != 0
            other_write = (val & 0x02) != 0
            other_read = (val & 0x04) != 0
            other_chattr = (val & 0x08) != 0
            other_delete = (val & 0x10) != 0
            perm_bits.append(
                f"Other: {'执行' if other_exec else '-'}"
                f"{'写' if other_write else '-'}"
                f"{'读' if other_read else '-'}"
                f"{'改属性' if other_chattr else '-'}"
                f"{'删除' if other_delete else '-'}")
            # Group 权限（bits5-9）
            group_exec = (val & 0x20) != 0
            group_write = (val & 0x40) != 0
            group_read = (val & 0x80) != 0
            group_chattr = (val & 0x100) != 0
            group_delete = (val & 0x200) != 0
            perm_bits.append(
                f"Group: {'执行' if group_exec else '-'}"
                f"{'写' if group_write else '-'}"
                f"{'读' if group_read else '-'}"
                f"{'改属性' if group_chattr else '-'}"
                f"{'删除' if group_delete else '-'}")
            # Owner 权限（bits10-14）
            owner_exec = (val & 0x400) != 0
            owner_write = (val & 0x800) != 0
            owner_read = (val & 0x1000) != 0
            owner_chattr = (val & 0x2000) != 0
            owner_delete = (val & 0x4000) != 0
            perm_bits.append(
                f"Owner: {'执行' if owner_exec else '-'}"
                f"{'写' if owner_write else '-'}"
                f"{'读' if owner_read else '-'}"
                f"{'改属性' if owner_chattr else '-'}"
                f"{'删除' if owner_delete else '-'}")
            # 保留位校验（bits15-31必须为0）
            reserved_ok = (val & 0xFFFF8000) == 0
            if not reserved_ok:
                perm_bits.append("⚠ 保留位（bits15-31）非0（非标准）")
            value = f"0x{val:08X}（{', '.join(perm_bits)}）"
        elif name == "ExtendedAttributeICB":
            value = long_ad_to_str(raw)
        elif name == "ImplementationIdentifier":
            # regid 类型（32字节），按字节显示
            value = regid_to_str(raw)
        elif name in ("InformationLength", "LogicalBlocksRecorded", "UniqueId"):
            val = struct.unpack('<Q', raw)[0]
            if name in ("InformationLength"):
                unit = "GB" if val > 1024 * 1024 * 1024 else "MB" if val > 1024 * 1024 else "KB"
                val_convert = val / (1024 * 1024 * 1024) if unit == "GB" else val / (
                            1024 * 1024) if unit == "MB" else val / 1024
                value = f"{val}字节 ({val_convert:.2f} {unit})"
            else:
                value = val
        elif name in (
        "Uid", "Gid", "RecordLength", "Checkpoint", "LengthofExtendedAttributes", "LengthofAllocationDescriptors"):
            val = struct.unpack('<I', raw)[0]
            value = f"{val}"
        elif name == "FileLinkCount":
            val = struct.unpack('<H', raw)[0]
            value = f"{val}"
        elif name in ("RecordFormat", "RecordDisplayAttributes"):
            val = struct.unpack('<B', raw)[0]
            value = f"0x{val:02X}"
        elif name in ("ExtendedAttributes", "AllocationDescriptors"):
            if size == 0:
                value = "无数据"
            else:
                icb_tag = entry[16:36]
                Flags = struct.unpack('<H', icb_tag[18:20])[0]
                ad_type = Flags & 0x07
                ad_type_map = {0: "短分配描述符", 1: "长分配描述符", 2: "扩展分配描述符", 3: "FID描述符"}
                ad_results = [f"AD类型={ad_type}（{ad_type_map.get(ad_type, '保留')}）"]

                ad_size_map = {0: 8, 1: 16, 2: 20}
                single_ad_size = ad_size_map.get(ad_type, 0)

                ad_start = 0
                remaining = size
                ad_idx = 0
                while remaining > 0:
                    if ad_type in (0, 1, 2):
                        if remaining < single_ad_size:
                            ad_results.append(f"AD[{ad_idx}] 剩余数据不足（{remaining}字节）")
                            break
                        ad_data = raw[ad_start:ad_start + single_ad_size]
                        if ad_type == 0:
                            ad_str = short_ad_to_str(ad_data)
                        elif ad_type == 1:
                            ad_str = long_ad_to_str(ad_data)
                        else:
                            ad_str = extent_ad_to_str(ad_data)
                        ad_results.append(f"AD[{ad_idx}] = {ad_str}")
                        ad_start += single_ad_size
                        remaining -= single_ad_size
                    elif ad_type == 3:
                        if remaining < 38:
                            ad_results.append(f"AD[{ad_idx}] FID固定头不足（{remaining}字节）")
                            break
                        fid_fixed = raw[ad_start:ad_start + 38]
                        L_FI_ad = struct.unpack('<B', fid_fixed[19:20])[0]
                        L_IU_ad = struct.unpack('<H', fid_fixed[36:38])[0]
                        # 计算FID总长度（含填充）
                        fid_total_len = 38 + L_IU_ad + L_FI_ad
                        if remaining < fid_total_len:
                            ad_results.append(f"AD[{ad_idx}] FID数据不足（需{fid_total_len}字节，剩余{remaining}字节）")
                            break
                        ad_data = raw[ad_start:ad_start + fid_total_len]
                        fid_str = parse_file_identifier_descriptor(ad_data, base_off + offset + ad_start)
                        ad_results.append(f"AD[{ad_idx}] = [FID] {fid_str}")
                        ad_start += fid_total_len
                        remaining -= fid_total_len
                    else:
                        ad_results.append(
                            f"AD[{ad_idx}] 未知类型（{ad_type}），原始数据：{raw[ad_start:ad_start + 16].hex()}...")
                        break
                    ad_idx += 1
                value = "; ".join(ad_results)
        elif size == 4:
            val = struct.unpack('<I', raw)[0]
            value = f"0x{val:08X}"
        elif size == 2:
            val = struct.unpack('<H', raw)[0]
            value = f"0x{val:04X}"
        elif size == 1:
            val = struct.unpack('<B', raw)[0]
            value = f"0x{val:02X}"
        else:
            value = raw[:16].hex(' ') + ("..." if size > 16 else "")
        # 原始值显示：长字段截断，保持输出统一
        raw_hex = raw[:16].hex(' ') + ("..." if size > 16 else "")
        info.append(dict(
            offset=base_off + offset,
            field=name,
            meaning=desc,
            raw=raw_hex,
            value=value
        ))
    return info


def parse_space_bitmap_descriptor(entry: bytes, base_off: int) -> List[Dict]:
    """Type264 Space Bitmap Descriptor（空间位图描述符)"""
    N_BT = struct.unpack('<I', entry[16:20])[0] if len(entry) >= 20 else 0
    N_B = struct.unpack('<I', entry[20:24])[0] if len(entry) >= 24 else 0
    min_N_B = (N_BT + 7) // 8

    fields = [
        ("TagIdentifier", 0, 2, "描述符类型（固定为264）"),
        ("DescriptorVersion", 2, 2, "描述符版本"),
        ("TagChecksum", 4, 1, "Tag校验和"),
        ("TagReserved", 5, 1, "保留字段（#00 byte）"),
        ("TagSerialNumber", 6, 2, "Tag序列号"),
        ("DescriptorCRC", 8, 2, "描述符CRC校验值"),
        ("DescriptorCRCLength", 10, 2, "CRC覆盖字节长度"),
        ("TagLocation", 12, 4, "Tag位置（逻辑块号）"),
        ("NumberOfBits(N_BT)", 16, 4, f"位图有效位数量 N_BT"),
        ("NumberOfBytes(N_B)", 20, 4, f"位图字节数 N_B = {N_B}（最小要求≥{min_N_B}字节）"),
        ("Bitmap", 24, N_B, f"位图数据（{N_B}字节，对应{N_BT}个逻辑块）"),
    ]

    info = []
    for name, offset, size, desc in fields:
        if offset + size > len(entry):
            info.append(dict(
                offset=base_off + offset,
                field=name,
                meaning=desc,
                raw="",
                value="字段超出数据范围（无效）"
            ))
            continue

        raw = entry[offset: offset + size]
        # 按标准类型精准解析
        if name == "TagIdentifier":
            val = struct.unpack('<H', raw)[0]
            value = f"0x{val:04X}（标准要求固定为264）"
        elif name == "TagReserved":
            val = struct.unpack('<B', raw)[0]
            value = f"0x{val:02X}（标准要求为#00）" if val == 0 else f"0x{val:02X}（非标准值）"
        elif name == "TagLocation":
            val = struct.unpack('<I', raw)[0]
            value = val
        elif name == "NumberOfBits(N_BT)":
            val = struct.unpack('<I', raw)[0]
            value = f"{val}（覆盖{val}个逻辑块）"
        elif name == "NumberOfBytes(N_B)":
            val = struct.unpack('<I', raw)[0]
            if val >= min_N_B:
                value = f"{val}字节（符合最小长度要求≥{min_N_B}字节）"
            else:
                value = f"{val}字节（⚠ 不符合最小长度要求，应为≥{min_N_B}字节）"
        elif name == "Bitmap":
            if size == 0:
                value = "无位图数据"
            else:
                # 位图每个位对应一个逻辑块，0=空闲/1=已用（标准未指定，按字节显示）
                value = raw[:16].hex(' ') + ("..." if size > 16 else "") + f"（共{size}字节，覆盖{N_BT}个逻辑块）"
        elif size == 4:
            val = struct.unpack('<I', raw)[0]
            value = f"0x{val:08X}"
        elif size == 2:
            val = struct.unpack('<H', raw)[0]
            value = f"0x{val:04X}"
        elif size == 1:
            val = struct.unpack('<B', raw)[0]
            value = f"0x{val:02X}"
        else:
            value = raw[:16].hex(' ') + ("..." if size > 16 else "")

        # 原始值显示：长字段截断，保持输出统一
        raw_hex = raw[:16].hex(' ') + ("..." if size > 16 else "")
        info.append(dict(
            offset=base_off + offset,
            field=name,
            meaning=desc,
            raw=raw_hex,
            value=value
        ))
    return info, N_B


def parse_extended_file_entry(entry: bytes, base_off: int) -> List[Dict]:
    """Type266 Extended File Entry（扩展文件条目）"""
    # 先读取动态长度字段（L_EA 和 L_AD），用于计算后续字段偏移
    L_EA = struct.unpack('<I', entry[208:212])[0] if len(entry) >= 212 else 0
    L_AD = struct.unpack('<I', entry[212:216])[0] if len(entry) >= 216 else 0

    fields = [
        ("TagIdentifier", 0, 2, "描述符类型（固定为266）"),
        ("DescriptorVersion", 2, 2, "描述符版本"),
        ("TagChecksum", 4, 1, "Tag校验和"),
        ("TagReserved", 5, 1, "保留字段（#00 byte）"),
        ("TagSerialNumber", 6, 2, "Tag序列号"),
        ("DescriptorCRC", 8, 2, "描述符CRC校验值"),
        ("DescriptorCRCLength", 10, 2, "CRC覆盖字节长度"),
        ("TagLocation", 12, 4, "Tag位置（逻辑块号）"),
        ("ICBTag", 16, 20, "ICB Tag"),
        ("Uid", 36, 4, "文件所有者用户ID"),
        ("Gid", 40, 4, "文件所有者组ID"),
        ("Permissions", 44, 4, "访问权限"),
        ("FileLinkCount", 48, 2, "文件链接数"),
        ("RecordFormat", 50, 1, "记录格式"),
        ("RecordDisplayAttributes", 51, 1, "记录显示属性"),
        ("RecordLength", 52, 4, "记录长度"),
        ("InformationLength", 56, 8, "文件信息长度（逻辑字节数）"),
        ("ObjectSize", 64, 8, "对象大小（所有流信息长度和）"),
        ("LogicalBlocksRecorded", 72, 8, "已记录逻辑块数（物理占用）"),
        ("AccessDateandTime", 80, 12, "访问时间"),
        ("ModificationDateandTime", 92, 12, "修改时间"),
        ("CreationDateandTime", 104, 12, "创建时间"),
        ("AttributeDateandTime", 116, 12, "属性修改时间"),
        ("Checkpoint", 128, 4, "检查点"),
        ("Reserved", 132, 4, "保留字段（#00 bytes）"),
        ("ExtendedAttributeICB", 136, 16, "扩展属性ICB"),
        ("StreamDirectoryICB", 152, 16, "流目录ICB"),
        ("ImplementationIdentifier", 168, 32, "实现者标识"),
        ("UniqueId", 200, 8, "文件唯一ID"),
        ("LengthofExtendedAttributes", 208, 4, f"扩展属性长度 L_EA = {L_EA} 字节"),
        ("LengthofAllocationDescriptors", 212, 4, f"分配描述符长度 L_AD = {L_AD} 字节"),
        # 动态字段（依赖 L_EA 和 L_AD）
        ("ExtendedAttributes", 216, L_EA, f"扩展属性数据（{L_EA}字节）"),
        ("AllocationDescriptors", 216 + L_EA, L_AD, f"分配描述符数据（{L_AD}字节）"),
    ]

    info = []
    for name, offset, size, desc in fields:
        if offset + size > len(entry):
            info.append(dict(
                offset=base_off + offset,
                field=name,
                meaning=desc,
                raw="",
                value="字段超出数据范围（无效）"
            ))
            continue

        raw = entry[offset: offset + size]
        if name == "TagIdentifier":
            val = struct.unpack('<H', raw)[0]
            value = f"0x{val:04X}（标准要求固定为266）"
        elif name in ("TagReserved", "Reserved"):
            val = struct.unpack('<I', raw)[0] if size == 4 else struct.unpack('<B', raw)[0]
            if (size == 1 and val == 0) or (size == 4 and val == 0):
                value = f"0x{val:02X}（符合标准，应为#00）" if size == 1 else f"0x{val:08X}（符合标准，应为#00）"
            else:
                value = f"0x{val:02X}（非标准值，应为#00）" if size == 1 else f"0x{val:08X}（非标准值，应为#00）"
        elif name =="TagLocation":
            val = struct.unpack('<I', raw)[0]
            value = val
        elif name == "ICBTag":
            icb_str = icbtag_to_str(raw)
            value = f"[ICB解析] {icb_str}"
        elif name in ("AccessDateandTime", "ModificationDateandTime", "CreationDateandTime", "AttributeDateandTime"):
            value = udf_timestamp_to_datetime(raw)
        elif name == "Permissions":
            val = struct.unpack('<I', raw)[0]
            # 复用Type261的权限位解析
            perm_bits = []
            other_exec = (val & 0x01) != 0
            other_write = (val & 0x02) != 0
            other_read = (val & 0x04) != 0
            other_chattr = (val & 0x08) != 0
            other_delete = (val & 0x10) != 0
            perm_bits.append(
                f"Other: {'执行' if other_exec else '-'}"
                f"{'写' if other_write else '-'}"
                f"{'读' if other_read else '-'}"
                f"{'改属性' if other_chattr else '-'}"
                f"{'删除' if other_delete else '-'}")
            group_exec = (val & 0x20) != 0
            group_write = (val & 0x40) != 0
            group_read = (val & 0x80) != 0
            group_chattr = (val & 0x100) != 0
            group_delete = (val & 0x200) != 0
            perm_bits.append(
                f"Group: {'执行' if group_exec else '-'}"
                f"{'写' if group_write else '-'}"
                f"{'读' if group_read else '-'}"
                f"{'改属性' if group_chattr else '-'}"
                f"{'删除' if group_delete else '-'}")
            owner_exec = (val & 0x400) != 0
            owner_write = (val & 0x800) != 0
            owner_read = (val & 0x1000) != 0
            owner_chattr = (val & 0x2000) != 0
            owner_delete = (val & 0x4000) != 0
            perm_bits.append(
                f"Owner: {'执行' if owner_exec else '-'}"
                f"{'写' if owner_write else '-'}"
                f"{'读' if owner_read else '-'}"
                f"{'改属性' if owner_chattr else '-'}"
                f"{'删除' if owner_delete else '-'}")
            reserved_ok = (val & 0xFFFF8000) == 0
            if not reserved_ok:
                perm_bits.append("⚠ 保留位（bits15-31)")
            value = f"0x{val:08X}（{', '.join(perm_bits)}）"
        elif name in ("ExtendedAttributeICB", "StreamDirectoryICB"):
            value = long_ad_to_str(raw)
        elif name == "ImplementationIdentifier":
            # regid 类型（32位字节），按字节显示
            value = regid_to_str(raw)
        elif name in ("InformationLength", "ObjectSize", "LogicalBlocksRecorded", "UniqueId"):
            val = struct.unpack('<Q', raw)[0]
            if name in ("InformationLength", "ObjectSize"):
                unit = "GB" if val > 1024 * 1024 * 1024 else "MB" if val > 1024 * 1024 else "KB"
                val_convert = val / (1024 * 1024 * 1024) if unit == "GB" else val / (
                            1024 * 1024) if unit == "MB" else val / 1024
                value = f"{val}字节 ({val_convert:.2f} {unit})"
            else:
                value = val
        elif name in ("Uid", "Gid", "RecordLength", "Checkpoint", "LengthofExtendedAttributes", "LengthofAllocationDescriptors"):
            val = struct.unpack('<I', raw)[0]
            value = f"{val}"
        elif name == "FileLinkCount":
            val = struct.unpack('<H', raw)[0]
            value = f"{val}"
        elif name in ("RecordFormat", "RecordDisplayAttributes"):
            val = struct.unpack('<B', raw)[0]
            value = f"0x{val:02X}"
        elif name in ("ExtendedAttributes", "AllocationDescriptors"):
            if size == 0:
                value = "无数据"
            else:
                icb_tag = entry[16:36]
                File_type = struct.unpack('<B', icb_tag[11:12])[0]
                Flags = struct.unpack('<H', icb_tag[18:20])[0]
                ad_type = Flags & 0x07
                ad_type_map = {0: "短分配描述符", 1: "长分配描述符", 2: "扩展分配描述符", 3: "单分配描述符"}
                ad_results = [f"\nAD类型={ad_type}（{ad_type_map.get(ad_type, '保留')}）"]
                ad_size_map = {0: 8, 1: 16, 2: 20}
                ad_start = 0
                remaining = size
                ad_idx = 0
                while remaining > 0:
                    if ad_type in (0, 1, 2):
                        single_ad_size = ad_size_map.get(ad_type, 0)
                        if remaining < single_ad_size:
                            ad_results.append(f"AD[{ad_idx}] 剩余数据不足（{remaining}字节）")
                            break
                        ad_data = raw[ad_start:ad_start + single_ad_size]
                        if ad_type == 0:
                            type_name = "short_ad"
                            ad_str = short_ad_to_str(ad_data)
                        elif ad_type == 1:
                            type_name = "long_ad"
                            ad_str = long_ad_to_str(ad_data)
                        elif ad_type == 2:
                            type_name = "extent_ad"
                            ad_str = extent_ad_to_str(ad_data)
                        ad_results.append(f"AD[{ad_idx}] = [{type_name}] {ad_str}")
                        ad_start += single_ad_size
                        remaining -= single_ad_size
                    elif ad_type == 3:
                        type_name = "FID"
                        if File_type == 5 :
                            byte_data = raw[ad_start:ad_start + remaining]
                            ad_results.append(f"流文件内容{byte_data[:16].hex(' ')}{('...' if size > 16 else '')}")
                            break
                        if remaining < 38:
                            ad_results.append(f"AD[{ad_idx}] FID固定头不足（{remaining}字节）")
                            break
                        fid_fixed = raw[ad_start:ad_start + 38]
                        L_FI = struct.unpack('<B', fid_fixed[19:20])[0]
                        L_IU = struct.unpack('<H', fid_fixed[36:38])[0]
                        fid_total_len = 38 + L_IU + L_FI + (4*((L_FI + L_IU + 38 + 3)//4) - (L_FI + L_IU + 38))
                        if remaining < fid_total_len:
                            ad_results.append(f"AD[{ad_idx}] FID数据不足（需{fid_total_len}字节，剩余{remaining}字节）")
                            break
                        ad_data = raw[ad_start:ad_start + fid_total_len]
                        fid_str = embedded_FID_to_str(ad_data, base_off + offset + ad_start)
                        ad_results.append(f"AD[{ad_idx}] = {type_name}{fid_str}")
                        ad_start += fid_total_len
                        remaining -= fid_total_len
                    else:
                        ad_results.append(
                            f"AD[{ad_idx}] 未知类型（{ad_type}）")
                        break
                    ad_idx += 1
                value = "\n".join(ad_results)

        elif size == 4:
            val = struct.unpack('<I', raw)[0]
            value = f"0x{val:08X}"
        elif size == 2:
            val = struct.unpack('<H', raw)[0]
            value = f"0x{val:04X}"
        elif size == 1:
            val = struct.unpack('<B', raw)[0]
            value = f"0x{val:02X}"
        else:
            value = raw[:16].hex(' ') + ("..." if size > 16 else "")

        # 原始值显示：长字段截断，保持输出统一
        raw_hex = raw[:16].hex(' ') + ("..." if size > 16 else "")
        info.append(dict(
            offset=base_off + offset,
            field=name,
            meaning=desc,
            raw=raw_hex,
            value=value
        ))
    return info

# ---------- 主函数 ----------
def dump_udf(raw: bytes):
    """UDF描述符解析主函数（按512字节逻辑扇区解析）"""
    if len(raw) % UDF_SECTOR_SIZE:
        print("⚠ 数据长度不是 512 的倍数，忽略尾部不足部分")
    idx = 0

    while idx < len(raw) // UDF_SECTOR_SIZE:
        base = idx * UDF_SECTOR_SIZE
        entry = raw[base: base + UDF_SECTOR_SIZE]
        tag_type = struct.unpack('<H', entry[0:2])[0] if len(entry) >= 2 else 0

        print(f"\n======= Descriptor #{idx}  (offset 0x{base:X}) =======")
        if tag_type == 0:
            print("End of descriptors (0x00)")
            break
        elif tag_type == 8:
            rows = parse_terminating_descriptor(entry, base)
        elif tag_type == 256:
            rows = parse_file_set_descriptor(entry, base)
        elif tag_type == 257:
            rows = parse_file_identifier_descriptor(entry, base)
        elif tag_type == 258:
            rows = parse_allocation_extent_descriptor(entry, base)
        elif tag_type == 259:
            rows = parse_indirect_entry(entry, base)
        elif tag_type == 260:
            rows = parse_terminal_entry(entry, base)
        elif tag_type == 261:
            rows = parse_file_entry(entry, base)
        elif tag_type == 264:
            rows, N_B = parse_space_bitmap_descriptor(entry, base)
            aviliable_Byte = UDF_SECTOR_SIZE -24
            remain_Bitmap = N_B - aviliable_Byte
            if remain_Bitmap > 0:
                skip_Sector = (remain_Bitmap + UDF_SECTOR_SIZE - 1) // UDF_SECTOR_SIZE
                idx += skip_Sector
                print(f"⚠ 位图数据长度超出当前扇区，将跳过后续{skip_Sector}个扇区 ⚠")
        elif tag_type == 266:
            rows = parse_extended_file_entry(entry, base)
        else:
            print(f"Unknown descriptor type 0x{tag_type:04X}")
            idx += 1
            continue

        print(textpad("偏移", 6), " |",
              textpad("字段", 24), " |",
              textpad("含义", 28), " |",
              textpad("十六进制", 28), " |", "解读")
        print("-" * 120)
        for r in rows:
            print(f"0x{r['offset']:4X}", " |",
                  textpad(r['field'], 24), " |",
                  textpad(r['meaning'], 28), " |",
                  textpad(r['raw'], 28), " |", r['value'])
        idx += 1


# ---------- 演示 ----------
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("请提供文件名作为命令行参数！python3 udf_dump.py udf_data.bin")
        sys.exit(1)
    filename = sys.argv[1]
    with open(filename, "rb") as f:
        raw = f.read()
    dump_udf(raw)
