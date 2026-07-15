# UDF Tools

UDF (Universal Disk Format) 文件系统 CLI 工具集 — 解析、分析、CRC修复、文件重命名一站式工具。

## 安装

### 从源码安装（推荐）

```bash
git clone https://github.com/yourname/udf-tools.git
cd udf-tools
pip install .
```

### 开发模式安装

```bash
pip install -e .
```

### 从GitHub直接安装

```bash
pip install git+https://github.com/yourname/udf-tools.git
```

### pipx 隔离安装（推荐生产环境）

```bash
pipx install .
```

## 命令一览

| 命令 | 说明 | 对应脚本 |
|------|------|----------|
| `udf-dump` | UDF 描述符解析器 | py-file-structure.py |
| `udf-rename` | UDF 内嵌 FID 重命名 | py-renamefile.py |
| `udf-crc` | UDF 描述符 CRC 校验修复 | py-crc.py |
| `udf-volume` | UDF 2.01 卷结构解析器 | py-volume-structure.py |

## 用法

### udf-dump — UDF 描述符解析器

```bash
udf-dump udf_image.bin
```

解析原始 UDF 二进制镜像，逐扇区展示所有描述符（文件集描述符、文件标识描述符、文件条目、扩展文件条目等），按字段逐一解读。

### udf-rename — UDF FID 重命名

```bash
udf-rename udf_image.bin 0x4000 "new_filename.txt"
```

重命名指定偏移处的扩展文件条目（EFE）中的内嵌文件标识描述符（FID）。工具会：
1. 列出指定偏移处发现的所有内嵌 FID
2. 提示你选择要重命名的那个
3. 更新 FID 并调整 EFE 元数据后写回

### udf-crc — UDF CRC 修复

```bash
udf-crc udf_image.hex
```

扫描 UDF hex dump 中的扩展文件条目（Tag ID 266），校验并修复 EFE 及其内嵌 FID 的 CRC-16-CCITT 校验和。输出写入 `<filename>-writeback.hex`。

### udf-volume — UDF 卷结构解析器

```bash
udf-volume blank-volume-structure.hex
```

解析 UDF 2.01 卷结构 hex dump（预期大小 0x18200 字节），展示关键字段：VRS、卷标、UUID、时间戳、逻辑块大小、分区信息等。

## 依赖

- Python >= 3.8
- wcwidth >= 0.2.0（终端文本对齐）

## 许可证

MIT