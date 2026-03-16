# mihoyo_sms_login

一个 **米游社短信验证码登录工具**，用于通过短信验证码登录米游社账号，并一次性获取/写入所需的登录凭证，方便对接 `MihoyoBBSTools` 的自动签到与米游币任务。

## 这个项目是干什么的？

这个脚本的主要目的：**获取 stoken 用于米游社签到任务**（以及相关自动任务）。

- 发送短信验证码到手机号
- 使用验证码登录米游社（优先 app 端点，失败自动回退 web 端点）
- 获取并输出：
  - `stoken_v2` + `mid` + `stuid`
  - `ltoken` + `cookie_token`
  - 完整 Cookie 字符串（v1 + v2 命名）
- 自动写入 `config.yaml`（默认 `test_config.yaml` 或由 `CONFIG_PATH` 指定）

> 典型用途：初始化或更新 MihoyoBBSTools 的登录凭证。

---

## 使用方法

### 1. 安装依赖

```bash
pip install httpx PyYAML pycryptodome
# 或使用 rsa 库替代 pycryptodome
pip install rsa
```

### 2. 发送验证码

```bash
python sms_login.py send <手机号>
```

若触发 Geetest，会提示 `aigis` 信息，再次发送需附带：

```bash
python sms_login.py send <手机号> --aigis "<session_id>;<base64_validate>"
```

### 3. 使用验证码登录

```bash
python sms_login.py login <手机号> <验证码>
```

登录成功后会自动：
- 换取 `ltoken` + `cookie_token`
- 写入 `config.yaml`

---

## 环境变量

- `CONFIG_PATH`：写入的配置文件路径（默认 `test_config.yaml`）

示例：

```bash
CONFIG_PATH=/path/to/config.yaml python sms_login.py login <手机号> <验证码>
```

---

## 输出内容

脚本运行成功后会输出并写入以下字段：

- `stoken_v2`
- `mid`
- `stuid`
- `ltoken`
- `cookie_token`
- 完整 Cookie 字符串

---

## 免责声明

本工具仅用于 **本人账号管理与自动化运维**。请勿用于任何违反米游社服务条款的用途。使用造成的账号风险由使用者自行承担。
