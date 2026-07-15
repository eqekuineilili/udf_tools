# 整个项目上传到GitHub 操作步骤

## 摘要

将当前 `udf-tools` 项目通过 Git 上传到 GitHub 仓库，包含初始化本地仓库、创建远程仓库、推送代码等完整流程。

---

## 操作步骤

### 步骤 1：初始化本地 Git 仓库

在项目根目录执行：

```bash
cd d:\pycharmProject\UDFparse
git init
```

### 步骤 2：创建 .gitignore（已存在）

项目已有 `.gitignore`，内容覆盖了 `__pycache__/`、`*.egg-info/`、`dist/`、`build/`、`.idea/`、`venv/` 等。确保 `.idea/` 已加入忽略列表（当前已有），避免 PyCharm 配置文件被提交。

### 步骤 3：添加所有文件并首次提交

```bash
git add .
git commit -m "Initial commit: UDF tools CLI toolkit"
```

### 步骤 4：在 GitHub 创建远程仓库

两种方式：

**方式 A — 浏览器操作：**
1. 打开 https://github.com/new
2. 仓库名填写 `udf-tools`
3. 描述：UDF file system parsing, analysis, CRC repair, and FID renaming CLI tools
4. 选择 **Public** 或 **Private**
5. **不要勾选** "Add a README file"（本地已有）
6. **不要勾选** ".gitignore" 和 "license"（本地已有）
7. 点击 "Create repository"

**方式 B — 使用 GitHub CLI（如已安装 `gh`）：**
```bash
gh auth login
gh repo create udf-tools --public --source=. --push
```

方式 B 会一步完成创建仓库、添加远程、推送，可以跳过步骤 5-6。

### 步骤 5：添加远程仓库并推送

```bash
git remote add origin https://github.com/你的用户名/udf-tools.git
git branch -M main
git push -u origin main
```

### 步骤 6：验证

- 浏览器打开 `https://github.com/你的用户名/udf-tools` 确认所有文件已上传
- 确认 `pyproject.toml`、`README.md`、`udf_tools/` 目录结构正确

---

## 后续更新

修改代码后，常规推送流程：

```bash
git add .
git commit -m "描述你的修改"
git push
```

---

## 注意事项

1. **推送前检查敏感信息**：确认 `pyproject.toml` 中的 `authors` 邮箱等个人信息为你期望公开的
2. **`.idea/` 已在 `.gitignore` 中**，PyCharm 配置文件不会被提交
3. 如果 GitHub 默认分支为 `main`，确保使用 `git branch -M main` 对齐
4. 首次推送如果提示认证失败，需要配置 GitHub Personal Access Token 或 SSH Key