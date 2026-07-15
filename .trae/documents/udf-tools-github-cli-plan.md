# UDF工具集 GitHub整合 + CLI命令化 实施方案

## 摘要

将4个UDF文件系统解析/处理Python脚本整合为标准的GitHub开源项目，通过 `pyproject.toml` + `console_scripts` 入口点机制，实现 `pip install .` 后即可在Linux上直接调用 `udf-dump`、`udf-rename`、`udf-crc`、`udf-volume` 四个命令，无需手动激活虚拟环境或 `python3` 前缀。核心策略：**runpy.run_path() 零侵入入口**，原 `.py` 文件内容完全不改。

---

## 一、当前状态分析

### 现有脚本清单

| 文件 | 功能 | 外部依赖 | CLI参数 |
|------|------|---------|---------|
| `py-file-structure.py` | UDF描述符解析器（Type 8/256/257/258/259/260/261/264/266） | `wcwidth` | `python3 py-file-structure.py <file>` |
| `py-renamefile.py` | UDF内嵌FID重命名工具 | 无 | `python3 py-renamefile.py <镜像> <EFE偏移> <新名字>` |
| `py-crc.py` | UDF描述符CRC校验修复 | `wcwidth`（冗余import） | `python3 py-crc.py <file>` |
| `py-volume-structure.py` | UDF 2.01卷结构解析器 | `wcwidth` | `python3 py-volume-structure.py <file>` |

### 关键约束

- **不改动原 `.py` 文件** — 用户明确要求
- `py-crc.py` 主逻辑全部在 `__main__` 块中，无独立 `main()` 函数
- `py-volume-structure.py` 第14-25行在模块顶层有副作用代码（import即执行文件读取）
- 需支持 Linux 直接命令调用（非 `python3` 虚拟环境方式）

---

## 二、推荐GitHub仓库目录结构

```
udf-tools/
├── pyproject.toml              # 项目元数据 + 构建配置 + 入口点声明
├── README.md                   # 项目说明（中英文）
├── LICENSE                     # MIT 许可证
├── .gitignore                  # Git忽略规则
├── udf_tools/                  # Python包目录
│   ├── __init__.py             # 包初始化
│   ├── cli_dump.py             # udf-dump 入口点
│   ├── cli_rename.py           # udf-rename 入口点
│   ├── cli_crc.py              # udf-crc 入口点
│   ├── cli_volume.py           # udf-volume 入口点
│   └── original/               # 原始脚本（原封不动移入）
│       ├── py-file-structure.py
│       ├── py-renamefile.py
│       ├── py-crc.py
│       └── py-volume-structure.py
└── tests/                      # 可选：测试目录
```

---

## 三、需要创建的新文件

### 3.1 pyproject.toml（项目根目录）

```toml
[build-system]
requires = ["setuptools>=61.0", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "udf-tools"
version = "1.0.0"
description = "UDF file system parsing, analysis, CRC repair, and FID renaming CLI tools"
readme = "README.md"
license = {text = "MIT"}
requires-python = ">=3.8"
authors = [
    {name = "Your Name", email = "your@email.com"},
]
keywords = ["udf", "filesystem", "forensics", "ecma-167"]
classifiers = [
    "Development Status :: 4 - Beta",
    "Environment :: Console",
    "Intended Audience :: Developers",
    "License :: OSI Approved :: MIT License",
    "Operating System :: POSIX :: Linux",
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.8",
    "Programming Language :: Python :: 3.9",
    "Programming Language :: Python :: 3.10",
    "Programming Language :: Python :: 3.11",
    "Programming Language :: Python :: 3.12",
    "Topic :: System :: Filesystems",
    "Topic :: Utilities",
]
dependencies = [
    "wcwidth>=0.2.0",
]

[project.urls]
Homepage = "https://github.com/yourname/udf-tools"
Repository = "https://github.com/yourname/udf-tools.git"
Issues = "https://github.com/yourname/udf-tools/issues"

[project.scripts]
udf-dump = "udf_tools.cli_dump:main"
udf-rename = "udf_tools.cli_rename:main"
udf-crc = "udf_tools.cli_crc:main"
udf-volume = "udf_tools.cli_volume:main"

[tool.setuptools.packages.find]
include = ["udf_tools*"]

[tool.setuptools.package-data]
udf_tools = ["original/*.py"]
```

### 3.2 udf_tools/__init__.py

```python
"""UDF Tools - UDF file system parsing and manipulation CLI toolkit."""

__version__ = "1.0.0"
```

### 3.3 四个入口点模块（udf_tools/cli_*.py）

每个入口点模块结构一致（仅6行），以 `cli_dump.py` 为例：

```python
"""Entry point for udf-dump: UDF descriptor dumper."""
import runpy
from pathlib import Path


def main():
    script = Path(__file__).parent / "original" / "py-file-structure.py"
    runpy.run_path(str(script), run_name="__main__")
```

其余三个同理，仅修改脚本文件名：
- `cli_rename.py` → `py-renamefile.py`
- `cli_crc.py` → `py-crc.py`
- `cli_volume.py` → `py-volume-structure.py`

### 3.4 README.md

包含安装说明、四个命令的用法示例、依赖说明、许可证信息。

### 3.5 .gitignore

标准Python项目忽略规则（`__pycache__/`、`*.egg-info/`、`dist/`、`build/`、`venv/`、IDE文件等）。

### 3.6 LICENSE

MIT许可证。

---

## 四、入口点映射总表

| CLI命令 | 入口模块 | 入口函数 | 原脚本 | 原始CLI参数 |
|---------|---------|---------|--------|------------|
| `udf-dump` | `udf_tools.cli_dump` | `main()` | `original/py-file-structure.py` | `<filename>` |
| `udf-rename` | `udf_tools.cli_rename` | `main()` | `original/py-renamefile.py` | `<img> <efe_offset> <new_name>` |
| `udf-crc` | `udf_tools.cli_crc` | `main()` | `original/py-crc.py` | `<filename>` |
| `udf-volume` | `udf_tools.cli_volume` | `main()` | `original/py-volume-structure.py` | `<filename>` |

---

## 五、安装和使用方式

### 方式一：开发模式安装（推荐调试）

```bash
cd udf-tools/
pip install -e .
```

安装后命令直接可用：
```bash
udf-dump myimage.bin
udf-rename myimage.bin 0x4000 "newfile.txt"
udf-crc myimage.hex
udf-volume volume-structure.hex
```

### 方式二：从GitHub直接安装

```bash
pip install git+https://github.com/yourname/udf-tools.git
```

### 方式三：构建wheel后安装

```bash
pip install build
python -m build
pip install dist/udf_tools-1.0.0-py3-none-any.whl
```

### 方式四：pipx隔离安装（推荐生产环境）

```bash
pipx install .
```

---

## 六、关键假设与决策

1. **runpy.run_path() 策略**：选择 `runpy.run_path` 而非 `subprocess` 或修改原脚本，因为前者零代码侵入、性能开销可忽略，且 `run_name="__main__"` 使原脚本的 `if __name__ == "__main__"` 块正常执行
2. **`[tool.setuptools.package-data]` 必须配置**：否则 `pip install` 后 `original/` 目录为空，入口点找不到脚本
3. **统一依赖 `wcwidth`**：`py-renamefile.py` 虽然不依赖 `wcwidth`，但作为工具集统一依赖更简洁，避免按需安装的复杂性
4. **原脚本硬编码消息不更新**：原脚本中的 `python3 py-xxx.py` usage提示保持不变（因为不改文件），用户在实际使用中以 `udf-xxx` 命令调用即可
5. **py-volume-structure.py 的模块顶层副作用**：使用 `runpy.run_path` 执行时行为与直接 `python3` 运行完全一致，不受影响

---

## 七、验证步骤

1. 在项目根目录执行 `pip install -e .`
2. 运行 `which udf-dump` 确认命令已注册到PATH
3. 运行 `udf-dump --help` 或提供测试文件验证各命令正常工作
4. 运行 `pip uninstall udf-tools` 确认可干净卸载
5. 在另一台Linux机器上执行 `pip install git+https://github.com/yourname/udf-tools.git` 验证远程安装