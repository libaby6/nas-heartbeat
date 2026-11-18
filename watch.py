#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GitHub Actions 侧的心跳巡检。

NAS 每 3 分钟往私有 Gist 的 hb.json 写一个时间戳；本脚本由 Actions 定时拉起，
读取 hb.json 判断是否超时，超时/恢复时通过 SMTP 发信，状态写回同一个 Gist 的 state.json。
"""
import json
import os
import smtplib
import ssl
import time
import urllib.request
from email.message import EmailMessage
from email.utils import formatdate

API = "https://api.github.com"


def envs(name, default=""):
    """Actions 里未定义的变量会传成空字符串，这里统一当"没配置"处理。"""
    v = os.environ.get(name)
    return v.strip() if v and v.strip() else default


def envf(name, default):
    try:
        return float(envs(name, str(default)))
    except ValueError:
        return float(default)


GIST_ID = envs("GIST_ID")
PAT = envs("GH_PAT")

SMTP_HOST = envs("SMTP_HOST", "smtp.qq.com")
SMTP_PORT = int(envf("SMTP_PORT", 465))
SMTP_USER = envs("SMTP_USER")
SMTP_PASS = envs("SMTP_PASS")
MAIL_FROM = envs("MAIL_FROM") or SMTP_USER
MAIL_TO = [x.strip() for x in envs("MAIL_TO").split(",") if x.strip()]

OFFLINE_MIN = envf("OFFLINE_AFTER_MIN", 15)
COOLDOWN_MIN = envf("COOLDOWN_MIN", 30)
# 同一次故障最多发几封告警；发满后就闭嘴，等恢复时再通知一次
MAX_ALERTS = max(1, int(envf("MAX_ALERTS_PER_INCIDENT", 2)))
NEVER_MIN = envf("NEVER_HEARTBEAT_MIN", 180)
LOSS_ALERT_PCT = envf("LOSS_ALERT_PCT", 40)
DISK_ALERT_PCT = envf("DISK_ALERT_PCT", 90)

DRY_RUN = envs("DRY_RUN") == "1"


# ---------------------------------------------------------------- 基础工具

def gh(method, path, body=None):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(
        API + path,
        data=data,
        method=method,
        headers={
            "Authorization": "Bearer " + PAT,
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
            "User-Agent": "nas-heartbeat-watch",
        },
    )
    with urllib.request.urlopen(req, timeout=25) as resp:
        raw = resp.read().decode("utf-8")
    return json.loads(raw) if raw.strip() else {}


def parse_json(text):
    if not text:
        return None
    try:
        return json.loads(text)
    except Exception:
        return None


def fmt_dur(ms):
    s = max(0, int(ms // 1000))
    if s < 60:
        return "%d秒" % s
    m = s // 60
    if m < 60:
        return "%d分钟" % m
    h = m // 60
    if h < 24:
        return "%d小时%d分钟" % (h, m % 60) if m % 60 else "%d小时" % h
    d = h // 24
    return "%d天%d小时" % (d, h % 24) if h % 24 else "%d天" % d


def fmt_time(ms):
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(int(ms) / 1000))


# ---------------------------------------------------------------- 状态机

def decide(now, hb, state):
    """返回 (level, reason, key, action)。

    key 是稳定的异常标识，用来判断"原因是否变了"——不能拿 reason 比，
    因为 reason 里含时长，每分钟都在变，会导致冷却期失效。
    action ∈ none/alert/repeat/recover。
    """
    offline_ms = OFFLINE_MIN * 60000
    cooldown_ms = COOLDOWN_MIN * 60000
    never_ms = NEVER_MIN * 60000

    level, reason, key = "ok", "", "ok"

    if hb and hb.get("ts"):
        silent = now - int(hb["ts"])
        if silent > offline_ms:
            level = "offline"
            key = "offline"
            reason = "已经%s没有收到心跳（阈值 %d 分钟）" % (fmt_dur(silent), OFFLINE_MIN)
        else:
            issues, codes = [], []
            loss = hb.get("wan_loss")
            if hb.get("wan_ok") is False or (isinstance(loss, (int, float)) and loss >= LOSS_ALERT_PCT):
                codes.append("loss")
                issues.append("外网探测失败或丢包 %.0f%%（阈值 %.0f%%）" % (
                    float(loss or 100), LOSS_ALERT_PCT))
            disk = hb.get("disk_pct")
            if isinstance(disk, (int, float)) and disk >= DISK_ALERT_PCT:
                codes.append("disk")
                issues.append("根分区占用 %.0f%%（阈值 %.0f%%）" % (float(disk), DISK_ALERT_PCT))
            if codes:
                level = "degraded"
                key = "degraded:" + ",".join(codes)
                reason = "；".join(issues)
    else:
        born = int(state.get("born") or now)
        if NEVER_MIN > 0 and now - born >= never_ms:
            level = "never"
            key = "never"
            reason = "自 %s 起从未收到任何心跳，已超过 %d 分钟" % (fmt_time(born), NEVER_MIN)

    prev_key = state.get("key")
    prev_level = state.get("level")

    # 这次故障里已经发过几封；换了故障类型（比如 offline → degraded）就重新计数
    sent = int(state.get("alert_count") or 0)
    if state.get("alert_key") != key:
        sent = 0

    if prev_level is None:
        action = "none" if level == "ok" else "alert"
    elif key == prev_key:
        if level == "ok":
            action = "none"
        elif sent >= MAX_ALERTS:
            action = "none"                      # 已达封顶，安静等恢复
        elif now - int(state.get("notified") or 0) >= cooldown_ms:
            action = "repeat"                    # 第二封（也是最后一封）
        else:
            action = "none"
    elif level == "ok":
        action = "recover"                       # 恢复：发一封，计数归零
    else:
        action = "alert" if sent < MAX_ALERTS else "none"

    return level, reason, key, action


def compose(now, hb, state, level, reason, action, sent_count=0):
    host = (hb or {}).get("host") or "casaos"
    if level == "offline":
        subject = "[NAS 离线] %s 已%s没有心跳" % (host, fmt_dur(now - int(hb["ts"])))
    elif level == "never":
        subject = "[NAS 未上报] %s 从未收到心跳" % host
    elif level == "degraded":
        subject = "[NAS 异常] %s：%s" % (host, reason)
    elif action == "recover":
        dur = fmt_dur(now - int(state.get("since") or now))
        subject = "[NAS 已恢复] %s 中断%s" % (host, dur)
    else:
        subject = "[NAS] %s 状态更新" % host

    lines = []
    if action == "recover":
        lines.append("%s 收到新的心跳，异常已解除。" % fmt_time(now))
        lines.append("异常从 %s 开始，持续 %s。" % (fmt_time(state.get("since") or now),
                                              fmt_dur(now - int(state.get("since") or now))))
    else:
        lines.append("检测时间：%s" % fmt_time(now))
        lines.append("判定：%s" % reason)

    lines.append("")
    if hb:
        last_ts = int(hb.get("ts") or 0)
        lines.append("最后一次心跳：%s（%s前）" % (fmt_time(last_ts), fmt_dur(now - last_ts)))
        rows = [
            ("主机", hb.get("host")),
            ("运行时长", ("%.1f 天" % (float(hb["uptime_s"]) / 86400)) if hb.get("uptime_s") else None),
            ("负载 1 分钟", hb.get("load1")),
            ("内存占用", ("%.0f%%" % hb["mem_pct"]) if isinstance(hb.get("mem_pct"), (int, float)) else None),
            ("网关", hb.get("gw_ip")),
            ("网关丢包", ("%.0f%%" % hb["gw_loss"]) if isinstance(hb.get("gw_loss"), (int, float)) else None),
            ("外网探测", ("正常" if hb["wan_ok"] else "失败") if "wan_ok" in hb else None),
            ("外网丢包", ("%.0f%%" % hb["wan_loss"]) if isinstance(hb.get("wan_loss"), (int, float)) else None),
            ("外网延迟", ("%.0f ms" % hb["wan_avg_ms"]) if isinstance(hb.get("wan_avg_ms"), (int, float)) else None),
            ("DNS", ("正常" if hb["dns_ok"] else "失败") if "dns_ok" in hb else None),
            ("根分区占用", ("%.0f%%" % hb["disk_pct"]) if isinstance(hb.get("disk_pct"), (int, float)) else None),
            ("Docker", ("正常" if hb["docker_ok"] else "失败") if "docker_ok" in hb else None),
            ("容器数", hb.get("containers")),
        ]
        for k, v in rows:
            if v not in (None, ""):
                lines.append("  · %s：%s" % (k, v))
    else:
        lines.append("这个 Gist 里还没有任何心跳记录。可能原因：")
        lines.append("  1. NAS 上的 Node-RED 心跳流程没启动")
        lines.append("  2. Gist ID 或 PAT 填错了（NAS 侧会看到 401/404）")
        lines.append("  3. NAS 连不上 api.github.com")

    lines.append("")
    if sent_count >= MAX_ALERTS and action != "recover":
        lines.append("本次故障已提醒 %d 封，达到上限，之后不再发信；恢复时会再通知一次。" % MAX_ALERTS)
    lines.append("-- 由 GitHub Actions 巡检生成，每 5 分钟一次")
    return subject, "\n".join(lines)


def send_mail(subject, body):
    if not (SMTP_USER and SMTP_PASS and MAIL_TO):
        raise RuntimeError("SMTP 配置不完整：需要 SMTP_USER / SMTP_PASS / MAIL_TO")
    msg = EmailMessage()
    msg["From"] = MAIL_FROM
    msg["To"] = ", ".join(MAIL_TO)
    msg["Subject"] = subject
    msg["Date"] = formatdate(localtime=True)
    msg.set_content(body)

    ctx = ssl.create_default_context()
    with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=ctx, timeout=25) as s:
        s.login(SMTP_USER, SMTP_PASS)
        s.send_message(msg)


# ---------------------------------------------------------------- 主流程

def main():
    now = int(time.time() * 1000)

    gist = gh("GET", "/gists/" + GIST_ID)
    files = {k: (v.get("content") or "") for k, v in (gist.get("files") or {}).items()}
    hb = parse_json(files.get("hb.json"))
    state = parse_json(files.get("state.json")) or {}
    if not state.get("born"):
        state["born"] = now

    level, reason, key, action = decide(now, hb, state)

    sent_before = int(state.get("alert_count") or 0)
    if state.get("alert_key") != key:
        sent_before = 0
    sent_after = sent_before + (1 if action in ("alert", "repeat") else 0)

    print("level=%s key=%s action=%s sent=%d/%d reason=%s"
          % (level, key, action, sent_after, MAX_ALERTS, reason or "-"))

    if action != "none":
        subject, body = compose(now, hb, state, level, reason, action, sent_after)
        print("发信：%s" % subject)
        if DRY_RUN:
            print("--- 正文 ---")
            print(body)
        else:
            send_mail(subject, body)

    prev_level = state.get("level")
    if prev_level is None or level != prev_level:
        # 离线时把起点对齐到最后一次心跳，这样恢复邮件能算出真实中断时长
        since = int(hb["ts"]) if (level == "offline" and hb and hb.get("ts")) else now
    else:
        since = int(state.get("since") or now)

    new_state = {
        "born": int(state.get("born") or now),
        "level": level,
        "key": key,
        "reason": reason,
        "since": since,
        "notified": now if action != "none" else int(state.get("notified") or 0),
        "checked": now,
        # 本次故障已发几封 + 是哪种故障（换了类型重新计数）；恢复后归零
        "alert_key": key,
        "alert_count": sent_after if level != "ok" else 0,
    }
    if new_state != state:
        patch = {"files": {"state.json": {"content": json.dumps(new_state, ensure_ascii=False)}}}
        if DRY_RUN:
            print("跳过写回（DRY_RUN）")
        else:
            gh("PATCH", "/gists/" + GIST_ID, patch)


if __name__ == "__main__":
    main()
