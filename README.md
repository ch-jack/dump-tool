# FiveM 服务器 Dump 工具

用于对 FiveM 服务器资源执行 Dump，并对已 Dump 的 FXAP 资源进行解密。

## 功能范围

- 包含：服务器 Dump
- 包含：FXAP 解密
- 不包含：模型修复

说明：仓库内仍保留原工具自带的模型修复相关文件，但该功能存在已知问题，本工具箱接入不会调用模型修复。

## 环境要求

- Windows 10 / Windows 11
- Python 3.7 或更高版本
- Java 8 或更高版本（推荐 Java 17，用于运行 `unluac54.jar`）
- FiveM 已安装并已进入目标服务器
- 需要读取 FiveM 进程 token 时，建议以管理员身份运行

## 安装

1. 下载或克隆本仓库。
2. 进入项目目录。
3. 运行 `install.bat` 安装依赖。

也可以手动安装依赖：

```bat
pip install -r requirements.txt
```

Lua 5.4 反编译依赖 Java。程序会依次检测 `--java` 指定位置、`JAVA_HOME` 和系统 `PATH`；没有可用 Java 时会在 Dump 前直接停止，不会再把未反编译的字节码误写成 `.lua`。

推荐安装 Eclipse Temurin Java 17 JRE：

https://adoptium.net/temurin/releases/?version=17&os=windows&arch=x64&package=jre

## 使用

交互模式：

```bat
python auto.py
```

直接传入目标地址：

```bat
python auto.py https://cfx.re/join/xxxx --token-choice 1
python auto.py 1.2.3.4:30120 --token-choice 1
python auto.py 1.2.3.4:30120 --token-choice 1 --java "C:\Program Files\Eclipse Adoptium\jre-17"
```

非交互模式，供 CK 工具箱调用：

```bat
python auto.py 1.2.3.4:30120 --token-choice 1 --resources all --output Output --report Output\_server_dump_report.json --non-interactive
```

`token_choice` 默认值为 `1`，表示自动扫描 FiveM 进程中的 token。需要手动 token 时可使用：

```bat
python auto.py 1.2.3.4:30120 --token-choice 2 --token YOUR_TOKEN
```

## 两步资源选择

只获取服务器资源清单，不创建输出或执行 Dump：

```bat
python auto.py 1.2.3.4:30120 --token-choice 1 --list-resources --non-interactive
```

正式 Dump 支持序号、精确资源名以及 `*`、`?` 通配符，多个条件用逗号分隔：

```bat
python auto.py 1.2.3.4:30120 --token-choice 1 --resources "esx_*,qb-*" --non-interactive
```

不传 `--resources` 且使用交互模式时，程序会在获取清单后显示编号菜单，预览匹配结果并要求确认。CK 工具箱使用独立的“获取资源清单”步骤，在菜单确认后通过 `--resources-file` 将精确资源名传给正式 Dump。

## 输出

- 解密后的文件默认写入 `Output`
- JSON 报告默认写入 `Output\_server_dump_report.json`
- Markdown 报告默认写入 `Output\_server_dump_report.md`
- 报告会记录实际 Java 路径、版本以及 Lua 反编译失败明细
- `unluac54.jar` 失败时保留 `.luac` 字节码和错误文件，不再伪装成解密成功的 `.lua`
- 执行过程中会输出 `CK_PROGRESS` 进度事件，供 CK 工具箱实时显示

## 注意事项

- 请只在你有权限分析的服务器或资源上使用。
- Dump 过程中不要关闭 FiveM 或本工具。
- 如果自动扫描 token 失败，请确认 FiveM 已进入服务器，或以管理员身份运行。
- 杀毒软件可能会根据本机策略对进程读取或打包工具提示风险。

## 免责声明

本项目仅用于学习、研究和授权场景。因误用造成的后果由使用者自行承担。
