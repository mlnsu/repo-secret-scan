# 仓库敏感信息扫描器

这是一个用 C11 编写的本地命令行工具，用于检查 Git 项目工作树中可能意外留下的密钥、令牌和密码。扫描只读本地文件，不上传代码或扫描结果。输出只包含仓库内路径、行号、规则名和 `[REDACTED]`，不会打印源代码行或命中值。

## 编译

需要 C11 编译器和 Git。Windows 可使用 MinGW-w64 GCC；Linux/macOS 可使用 GCC 或 Clang。

```sh
cc -std=c11 -O2 -Wall -Wextra main.c -o secret-scan
```

Windows PowerShell 示例：

```powershell
gcc -std=c11 -O2 -Wall -Wextra main.c -o secret-scan.exe
```

## 使用

扫描当前仓库：

```sh
./secret-scan
```

扫描一个或多个其他仓库：

```sh
./secret-scan /path/to/repo-a /path/to/repo-b
```

Windows 示例：

```powershell
.\secret-scan.exe C:\path\to\repo-a C:\path\to\repo-b
```

退出码：`0` 表示未发现命中，`1` 表示至少一个仓库发现疑似敏感信息，`2` 表示仓库或 Git 错误。

## 扫描范围

- 通过 `git ls-files` 扫描 Git 已跟踪文件和未被 Git 忽略的未跟踪文件。
- 遵循仓库 `.gitignore`，跳过 `.git`、虚拟环境、依赖目录、构建产物和缓存目录。
- 跳过大于 1 MB 的文件、二进制文件和符号链接。
- 只检查当前工作树；不检查提交历史、Git LFS 远端内容或忽略文件。
- 支持私钥标记、AWS access key、GitHub/Slack/GCP 凭据、JWT，以及常见密码或密钥赋值字段。

检测规则无法保证发现所有秘密，编码或拆分的凭据可能漏过，示例值也可能误报。请人工复核；真实密钥泄漏后，应在对应服务撤销或轮换凭据。

## 开发说明

当前 C11 源码入口是 `main.c`。
