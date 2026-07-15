#!/usr/bin/env python3
"""
UDF 2.01 解析器
输入：blank-volume-structure.hex
输出：终端表格展示关键信息
"""
from pathlib import Path
from struct import unpack
from wcwidth import wcswidth
from datetime import datetime, timedelta
import sys
import struct
# --------------------------------------------------
if len(sys.argv) < 2:
    print("请提供文件名作为命令行参数！python3 py-volume-structure.py blank-volume-structure.hex")
    sys.exit(1)
# 获取文件名并读取数据
filename = sys.argv[1]
hex_file = Path(filename)
if not hex_file.exists():
    raise SystemExit(f'未找到文件: {filename}')
raw = hex_file.read_bytes()
if len(raw) != 0x18200:
    raise SystemExit(f'文件长度不是 0x18200 字节，而是 {len(raw)}')
print(f"成功读取文件：{filename}，长度：{len(raw)} 字节（预期 512*193=98816 字节）\n")


# --------------------------------------------------
# 小工具
def hex_str(off, size):
    """提取指定偏移和长度的十六进制字符串（连续，大写），超长时截断"""
    if off + size > len(raw):
        return "超出文件长度"
    data = raw[off:off + size]
    if size <= 8:
        return data.hex().upper()
    else:
        truncated = data[:8].hex().upper()
        return f"{truncated}..."


def ascii_safe(bs):
    """二进制转安全ASCII（非可打印字符用.替代）"""
    return ''.join(chr(b) if 32 <= b <= 126 else '.' for b in bs)


def dstring_to_str(b: bytes) -> str:
    """UDF dstring 格式解析（ASCII，尾部补0）"""
    try:
        return b.decode('ascii').split('\x00')[0]
    except UnicodeDecodeError:
        return "<decode error>"


def textpad(text, width):
    """文本补空格对齐（适配宽字符）"""
    return text + ' ' * (width - wcswidth(text))

def udf_timestamp_to_datetime(data):
    """
    转换UDF时间戳（12字节）为北京时间格式
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
        return "无效时间戳（长度错误）"
    # 2. 空时间戳判断：全0表示未指定
    if all(b == 0 for b in data):
        return "时间戳未指定"
    
    try:
        # ========== 第一步：解析Type and Time Zone（前2字节） ==========
        # 解包前2字节为小端16位无符号整数
        type_timezone = struct.unpack('<H', data[0:2])[0]
        # 拆分：最高4位=Type，低12位=时区偏移（分钟）
        ts_type = (type_timezone >> 12) & 0x0F  # 提取最高4位（Type）
        tz_offset_raw = type_timezone & 0x0FFF   # 提取低12位（原始时区偏移值）
        
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

# --------------------------------------------------
# UDF 关键字段定义
fields = [
    (0x0000, 6, 'VRS起始（BEA01启动入口）',	lambda b: ascii_safe(b[1:])), 
    (0x0800, 6, 'NSR03导航扇区记录',		lambda b: ascii_safe(b[1:])),  
    (0x1000, 6, 'TEA01终端入口区域', 		lambda b: ascii_safe(b[1:])), 
    (0x400C, 4, '元数据起始扇区',		lambda b: unpack('<I', b)[0]),
    (0x4018, 32, '卷标',				lambda b: dstring_to_str(b)),
    (0x4049, 16, 'UUID', 			lambda b: ascii_safe(b)),  
    (0x40C8, 16, '字符集', 			lambda b: ascii_safe(b[1:])),  
    (0x4159, 18, '构建工具', 			lambda b: ascii_safe(b[1:])), 
    (0x4178, 12, '卷创建时间戳',			lambda b: udf_timestamp_to_datetime(b)),
    (0x42D4, 4, '逻辑块大小(字节)', 		lambda b: unpack('<I', b)[0]),
    (0x44B8, 4, '文件写入类型',			lambda b:(lambda val:
                                                    "未定义" if val == 0
                                                    else "只读" if val == 1
                                                    else "一次写入" if val == 2
                                                    else "可重写" if val == 3
                                                    else "可覆写" if val == 4
                                                    else f"留作未来标准({val})"
                                                     )(unpack('<I', b)[0])
                                                    if len(b) == 4 else "无效数据"),
    (0x44BC, 4, '数据区起始扇区',		lambda b: unpack('<I', b)[0]),
    (0x4A0C, 4,'终止描述符扇区',		lambda b: unpack('<I', b)[0]),
    (0x800C, 4, 'LVID逻辑卷识别符起始', 		lambda b: unpack('<I', b)[0]),
    (0x8010, 12, '卷更新/校验时间戳',		lambda b: udf_timestamp_to_datetime(b)),
    (0x804C, 4, '逻辑卷关联分区总数', 		lambda b: unpack('<I', b)[0]),
    (0x8050, 4, '空闲数据区扇区数', 			lambda b: unpack('<I', b)[0]),
    (0x8054, 4, '用户数据区大小',              lambda b: unpack('<I', b)[0]),
    (0x18010, 4, 'MVDS数据长度', 		lambda b: unpack('<I', b)[0]),
    (0x18014, 4, 'MVDS起始扇区', 		lambda b: unpack('<I', b)[0]),
    (0x18018, 4, 'RVDS数据长度', 		lambda b: unpack('<I', b)[0]),
    (0x1801C, 4, 'RVDS起始扇区', 		lambda b: unpack('<I', b)[0]),
]

# --------------------------------------------------
# 输出表头
print(textpad("偏移", 8), textpad("长度", 6),
      textpad("字段名", 26), textpad("十六进制值", 40), "解析值")

# 输出数据
for off, size, name, fn in fields:
    val = fn(raw[off:off+size])
    hx  = hex_str(off, size)
    print(textpad(f"0x{off:02X}", 8),
          textpad(str(size), 6),
          textpad(name, 26),
          textpad(hx, 40),
          val)