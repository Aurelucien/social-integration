# 社交整合

这是一个面向个人消息资料的本地、只读整合项目。目前的主要成果是
[Personal Social Inbox](personal-social-inbox/README.md)：它把经过明确选择和导出的
微信、QQ、钉钉消息规范化到本地 SQLite 数据库，并通过只读 Codex 工具提供检索、
上下文、附件、摘要和待人工确认的重要事件候选。

本仓库当前按“协作预览”维护，适合分享给受信任的协作者共同开发和审阅；它不是面向
公众的一键安装产品，也不承诺跨平台、长期后台运行或对任意客户端版本兼容。

## 项目边界

- 源应用、源数据库和已有导出只读；项目不会发送、撤回或修改消息。
- 导入只写入项目自己的私有数据目录，不写回微信、QQ 或钉钉。
- 不包含账号登录、凭据采集、客户端注入、系统安全设置修改或自动绕过验证。
- 事件候选和摘要属于派生结果，不能替代源消息或人工确认。
- 实验目录中的采集、格式研究与主插件的稳定只读接口分开维护。

更完整的安全说明见 [SECURITY.md](personal-social-inbox/SECURITY.md)，架构和数据边界见
[architecture.md](personal-social-inbox/docs/architecture.md)。

## 仓库结构

```text
personal-social-inbox/          主插件、命令行、只读 MCP 服务和测试
experiments/wechat-4.1.7-poc/  微信 4.1.7 的受限实验与增量复制原型
experiments/qq-qce-docker/      QQ/QCE 的隔离导出辅助环境
experiments/dingtalk-8.3.5-poc/ 钉钉 8.3.5 的受限格式实验
third_party/                    已记录许可证的第三方参考项目
```

`recovery/`、各实验的 `private/`、插件的 `data/` 等本地材料均被 Git 忽略，不属于可分享
内容。

## 本地启动

要求 Python 3.11 或更高版本。运行时本身只依赖 Python 标准库。

```bash
cd personal-social-inbox
python3 -m venv .venv
source .venv/bin/activate
python -m unittest discover -s tests -v
```

主脚本会直接加载 `src/` 中的代码，因此本地开发和测试无需安装依赖。如果希望获得
`personal-social-inbox` 控制台命令，可在能够取得 `setuptools>=68` 的环境中另外运行
`python -m pip install -e .`；这不是参与协作的前置条件。

用仓库自带的虚构示例初始化一个隔离数据目录：

```bash
export PERSONAL_SOCIAL_INBOX_HOME=/tmp/personal-social-inbox-demo
python social_inbox.py init
python social_inbox.py import examples/sample-export/export.json
python social_inbox.py stats
```

如需配置采集器心跳，请复制
`personal-social-inbox/examples/collector-config.example.json` 到仓库外，再填写本机路径和
账号绑定。不要把真实配置提交到 Git。

## 协作方式

开始改动前请先阅读 [CONTRIBUTING.md](CONTRIBUTING.md)。一般改动保持小而可审阅，并在
`personal-social-inbox/` 下运行完整测试。涉及真实消息、账号、凭据、客户端注入、解密、
源应用写操作或后台常驻服务的方案，不属于默认协作范围，需要单独讨论和明确授权。

## 分享前检查

建议只通过 Git 分享已审阅的提交，而不是压缩整个工作目录。分享前至少检查：

```bash
git status --short
git grep -n -I -E '/U[s]ers/|BEGIN [A-Z ]*PRIVATE K[E]Y|api[_-]?key|client[_-]?secret'
```

同时确认没有强制加入被 `.gitignore` 排除的数据库、附件、导出批次、运行日志或私有配置。

## 发布状态与许可证

当前版本定位为小范围协作预览，不需要安装器、签名制品、自动发布流水线或正式兼容性
承诺。仓库尚未选择开源许可证；在决定公开发布前，应先确认许可证、第三方归属说明和
可公开支持的客户端范围。受信任协作者之间的代码分享也不应包含任何真实个人消息数据。
