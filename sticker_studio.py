import argparse
import asyncio
import csv
import datetime as dt
import hashlib
import inspect
import io
import json
import os
import re
import socket
import sqlite3
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import aiohttp
import qrcode
from dotenv import load_dotenv
from aiohttp import web
from PIL import Image, ImageDraw, ImageFont, ImageOps
from rich.console import Console
from rich.table import Table

MAX_STICKER_SIZE = 512 * 1024
STICKER_CANVAS = (512, 512)
STATIC_SUFFIXES = {".png", ".jpg", ".jpeg", ".webp"}
STATE_PREFIX = ".sticker_state_"
VISUAL_MODES = {"clean", "maker", "brand", "circle", "pixel", "bw"}
FIT_MODES = {"contain", "cover"}
CLONE_MODES = {"copy", "studio"}
VISUAL_MODE_LABELS = {
    "maker": "署名增强",
    "clean": "纯净",
    "brand": "品牌条",
    "circle": "圆形裁切",
    "pixel": "像素风",
    "bw": "黑白",
}
FIT_MODE_LABELS = {
    "contain": "完整保留",
    "cover": "铺满裁切",
}
CLONE_MODE_LABELS = {
    "studio": "工作室重渲染",
    "copy": "尽量原样复制",
}
MAKE_TARGET_MODE_LABELS = {
    "ask": "每次询问",
    "join": "默认加入当前包",
    "new": "默认新建包",
}
DEFAULT_USER_SETTINGS = {
    "watermark": "",
    "mode": "maker",
    "fit_mode": "contain",
    "clone_mode": "studio",
    "make_target_mode": "ask",
    "current_pack_short": "",
    "current_pack_title": "",
}
DEFAULT_USAGE_POLICY = {
    "free_clone": 3,
    "free_make": 5,
    "invite_reward_clone": 2,
    "invite_reward_make": 3,
    "enforce_limits": True,
    "daily_reset_enabled": True,
    "daily_free_clone": 1,
    "daily_free_make": 2,
}
DEFAULT_EXTERNAL_LINKS = {
    "group": "",
    "author": "",
}
ADMIN_INPUT_TTL_SECONDS = 600
KNOWN_COMPROMISED_TOKEN_SHA256 = {
    "614ae22034739b2d4f6ab49461904e6dc6728431f48acb680d4a4ff3e5d84fcd",
    "981d35b39807eb060ae45089779bfeb60b04821abebcd5d8c31d6a9e3fa02256",
}

console = Console()


def validate_bot_token(token: str) -> tuple[bool, str]:
    raw = (token or "").strip()
    if not raw:
        return False, "环境变量或 .env 中缺少 BOT_TOKEN"

    lowered = raw.lower()
    if ("your-bot-token" in lowered) or raw.startswith("123456:"):
        return False, "检测到示例 BOT_TOKEN，请替换为真实 Token"

    if not re.fullmatch(r"\d{6,}:[A-Za-z0-9_-]{30,}", raw):
        return False, "BOT_TOKEN 格式不正确（应为 <数字>:<密钥>）"

    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    if digest in KNOWN_COMPROMISED_TOKEN_SHA256:
        return False, "检测到该 BOT_TOKEN 曾公开暴露，已触发安全拦截"

    return True, ""


def _atomic_write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp.{os.getpid()}.{int(time.time() * 1000)}")
    tmp.write_text(
        json.dumps(data, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    os.replace(tmp, path)


def _sqlite_init(db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS kv_store (k TEXT PRIMARY KEY, v TEXT NOT NULL)"
        )
        conn.execute(
            "CREATE TABLE IF NOT EXISTS audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL, actor INTEGER NOT NULL, action TEXT NOT NULL, detail TEXT NOT NULL, target INTEGER, extra_json TEXT)"
        )
        conn.commit()


def _sqlite_get_json(db_path: Path, key: str) -> Any:
    _sqlite_init(db_path)
    with sqlite3.connect(str(db_path)) as conn:
        row = conn.execute("SELECT v FROM kv_store WHERE k = ?", (key,)).fetchone()
    if not row:
        return None
    try:
        return json.loads(str(row[0]))
    except json.JSONDecodeError:
        return None


def _sqlite_set_json(db_path: Path, key: str, value: Any) -> None:
    _sqlite_init(db_path)
    raw = json.dumps(value, ensure_ascii=False)
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            "INSERT INTO kv_store(k, v) VALUES(?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v",
            (key, raw),
        )
        conn.commit()


class TelegramAPIError(RuntimeError):
    pass


class TelegramBotClient:
    def __init__(
        self,
        token: str,
        *,
        api_base: str | None = None,
        file_base: str | None = None,
        proxy: str | None = None,
        trust_env: bool = True,
        force_ipv4: bool = False,
    ) -> None:
        self.token = token
        api_root = (api_base or "https://api.telegram.org").strip().rstrip("/")
        file_root = (file_base or api_root).strip().rstrip("/")
        self.base_url = f"{api_root}/bot{token}"
        self.file_base = f"{file_root}/file/bot{token}"
        self.proxy = (proxy or "").strip() or None
        self.trust_env = trust_env
        self.force_ipv4 = force_ipv4
        self.session: aiohttp.ClientSession | None = None

    async def __aenter__(self) -> "TelegramBotClient":
        timeout = aiohttp.ClientTimeout(total=120)
        connector = aiohttp.TCPConnector(
            family=socket.AF_INET if self.force_ipv4 else socket.AF_UNSPEC,
            ttl_dns_cache=300,
        )
        self.session = aiohttp.ClientSession(
            timeout=timeout,
            trust_env=self.trust_env,
            connector=connector,
        )
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if self.session:
            await self.session.close()

    async def call(
        self,
        method: str,
        data: dict[str, Any] | None = None,
        files: dict[str, tuple[str, bytes, str]] | None = None,
    ) -> Any:
        if self.session is None:
            raise RuntimeError("客户端尚未启动")

        url = f"{self.base_url}/{method}"
        payload = data or {}

        for attempt in range(3):
            try:
                req_kwargs: dict[str, Any] = {}
                if self.proxy:
                    req_kwargs["proxy"] = self.proxy
                if files:
                    form = aiohttp.FormData()
                    for key, value in payload.items():
                        if isinstance(value, (dict, list)):
                            form.add_field(key, json.dumps(value, ensure_ascii=False))
                        else:
                            form.add_field(key, str(value))

                    for field, (filename, content, content_type) in files.items():
                        form.add_field(
                            field,
                            content,
                            filename=filename,
                            content_type=content_type,
                        )

                    async with self.session.post(url, data=form, **req_kwargs) as resp:
                        body = await resp.json(content_type=None)
                else:
                    async with self.session.post(url, json=payload, **req_kwargs) as resp:
                        body = await resp.json(content_type=None)

                if not body.get("ok"):
                    raise TelegramAPIError(
                        f"{method} 调用失败: {body.get('description', '未知错误')}"
                    )
                return body["result"]
            except (aiohttp.ClientError, asyncio.TimeoutError, json.JSONDecodeError) as exc:
                if attempt == 2:
                    raise TelegramAPIError(f"{method} 网络错误: {exc}") from exc
                await asyncio.sleep(1.2 * (attempt + 1))

    async def download_file(self, file_id: str) -> bytes:
        if self.session is None:
            raise RuntimeError("客户端尚未启动")

        file_info = await self.call("getFile", {"file_id": file_id})
        file_path = file_info["file_path"]
        file_url = f"{self.file_base}/{file_path}"

        for attempt in range(3):
            try:
                req_kwargs: dict[str, Any] = {}
                if self.proxy:
                    req_kwargs["proxy"] = self.proxy
                async with self.session.get(file_url, **req_kwargs) as resp:
                    resp.raise_for_status()
                    return await resp.read()
            except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
                if attempt == 2:
                    raise TelegramAPIError(f"下载文件失败 {file_id}: {exc}") from exc
                await asyncio.sleep(1.2 * (attempt + 1))

    async def send_message(
        self,
        chat_id: int,
        text: str,
        reply_to_message_id: int | None = None,
        reply_markup: dict[str, Any] | None = None,
        parse_mode: str | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "chat_id": chat_id,
            "text": text,
            "disable_web_page_preview": True,
        }
        if reply_to_message_id:
            payload["reply_parameters"] = {"message_id": reply_to_message_id}
        if reply_markup:
            payload["reply_markup"] = reply_markup
        if parse_mode:
            payload["parse_mode"] = parse_mode
        return await self.call("sendMessage", payload)

    async def edit_message_text(
        self,
        chat_id: int,
        message_id: int,
        text: str,
        reply_markup: dict[str, Any] | None = None,
        parse_mode: str | None = None,
    ) -> None:
        await self.call(
            "editMessageText",
            {
                "chat_id": chat_id,
                "message_id": message_id,
                "text": text,
                "disable_web_page_preview": True,
                **({"reply_markup": reply_markup} if reply_markup else {}),
                **({"parse_mode": parse_mode} if parse_mode else {}),
            },
        )

    async def send_photo(
        self,
        chat_id: int,
        photo: bytes,
        caption: str | None = None,
        reply_markup: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {"chat_id": chat_id}
        if caption:
            payload["caption"] = caption
        if reply_markup:
            payload["reply_markup"] = reply_markup
        files = {"photo": ("invite_card.png", photo, "image/png")}
        return await self.call("sendPhoto", payload, files=files)

    async def send_document(
        self,
        chat_id: int,
        document: bytes,
        *,
        filename: str = "report.csv",
        caption: str | None = None,
        reply_markup: dict[str, Any] | None = None,
        mime_type: str = "text/csv",
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {"chat_id": chat_id}
        if caption:
            payload["caption"] = caption
        if reply_markup:
            payload["reply_markup"] = reply_markup
        files = {"document": (filename, document, mime_type)}
        return await self.call("sendDocument", payload, files=files)

    async def answer_callback_query(self, callback_query_id: str, text: str | None = None) -> None:
        payload: dict[str, Any] = {"callback_query_id": callback_query_id}
        if text:
            payload["text"] = text
            payload["show_alert"] = False
        await self.call("answerCallbackQuery", payload)


class StateStore:
    def __init__(self, short_name: str) -> None:
        self.path = Path(f"{STATE_PREFIX}{short_name}.json")
        db_raw = os.getenv("BOT_SQLITE_PATH", "").strip()
        self.sqlite_path = Path(db_raw) if db_raw else None
        self.sqlite_key = f"state:{short_name}"

    def load(self) -> dict[str, Any]:
        if self.sqlite_path is not None:
            raw_db = _sqlite_get_json(self.sqlite_path, self.sqlite_key)
            if isinstance(raw_db, dict):
                return raw_db
        if not self.path.exists():
            return {"created": False, "done": []}
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return {"created": False, "done": []}
        if not isinstance(raw, dict):
            return {"created": False, "done": []}
        if self.sqlite_path is not None:
            _sqlite_set_json(self.sqlite_path, self.sqlite_key, raw)
        return raw

    def save(self, data: dict[str, Any]) -> None:
        if self.sqlite_path is not None:
            _sqlite_set_json(self.sqlite_path, self.sqlite_key, data)
            return
        _atomic_write_json(self.path, data)


class UserPrefsStore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or Path(".user_prefs.json")
        db_raw = os.getenv("BOT_SQLITE_PATH", "").strip()
        self.sqlite_path = Path(db_raw) if db_raw else None
        self.sqlite_key = "user_prefs"

    def load(self) -> dict[str, Any]:
        if self.sqlite_path is not None:
            raw_db = _sqlite_get_json(self.sqlite_path, self.sqlite_key)
            if isinstance(raw_db, dict):
                return raw_db
        if not self.path.exists():
            return {}
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return {}
        if not isinstance(raw, dict):
            return {}
        if self.sqlite_path is not None:
            _sqlite_set_json(self.sqlite_path, self.sqlite_key, raw)
        return raw

    def save(self, data: dict[str, Any]) -> None:
        if self.sqlite_path is not None:
            _sqlite_set_json(self.sqlite_path, self.sqlite_key, data)
            return
        _atomic_write_json(self.path, data)

    def get_user_watermark(self, user_id: int) -> str | None:
        data = self.load()
        user = data.get(str(user_id), {})
        wm = (user.get("watermark") or "").strip()
        return wm or None

    def set_user_watermark(self, user_id: int, watermark: str | None) -> None:
        data = self.load()
        key = str(user_id)
        item = data.get(key, {})
        if watermark:
            item["watermark"] = watermark
            data[key] = item
        elif key in data:
            if "watermark" in data[key]:
                del data[key]["watermark"]
            if not data[key]:
                del data[key]
        self.save(data)

    def _get_user_data(self, data: dict[str, Any], user_id: int) -> dict[str, Any]:
        raw = data.get(str(user_id), {})
        if isinstance(raw, dict):
            return dict(raw)
        return {}

    def get_user_settings(self, user_id: int) -> dict[str, Any]:
        data = self.load()
        raw = self._get_user_data(data, user_id)
        out = dict(DEFAULT_USER_SETTINGS)
        # Backward compatibility for old keys
        if (not raw.get("current_pack_short")) and raw.get("auto_pack_short"):
            raw["current_pack_short"] = raw.get("auto_pack_short")
        if (not raw.get("current_pack_title")) and raw.get("auto_pack_title"):
            raw["current_pack_title"] = raw.get("auto_pack_title")
        for key in out:
            val = raw.get(key)
            if val is None:
                continue
            out[key] = str(val)
        return out

    def set_user_pref(self, user_id: int, key: str, value: str | None) -> None:
        if key not in DEFAULT_USER_SETTINGS:
            raise ValueError(f"不支持的用户偏好键: {key}")

        data = self.load()
        uid = str(user_id)
        user = self._get_user_data(data, user_id)

        if value is None or str(value).strip() == "":
            if key in user:
                del user[key]
        else:
            user[key] = str(value).strip()

        if user:
            data[uid] = user
        elif uid in data:
            del data[uid]
        self.save(data)

    def touch_pack(self, user_id: int, short_name: str, title: str | None = None, count_add: int = 1) -> None:
        clean_short = short_name.strip()
        if not clean_short:
            return

        now = dt.datetime.now(dt.timezone.utc).isoformat()
        data = self.load()
        uid = str(user_id)
        user = self._get_user_data(data, user_id)

        if title:
            clean_title = title.strip()
        else:
            clean_title = (user.get("current_pack_title") or "").strip() or clean_short

        user["current_pack_short"] = clean_short
        user["current_pack_title"] = clean_title

        packs = user.get("packs", [])
        if not isinstance(packs, list):
            packs = []

        found = False
        for item in packs:
            if not isinstance(item, dict):
                continue
            if (item.get("short_name") or "") != clean_short:
                continue
            if clean_title:
                item["title"] = clean_title
            item["count"] = int(item.get("count", 0)) + max(0, int(count_add))
            item["updated_at"] = now
            found = True
            break

        if not found:
            packs.append(
                {
                    "short_name": clean_short,
                    "title": clean_title,
                    "count": max(0, int(count_add)),
                    "updated_at": now,
                }
            )

        packs = [p for p in packs if isinstance(p, dict) and p.get("short_name")]
        packs.sort(key=lambda p: str(p.get("updated_at", "")), reverse=True)
        user["packs"] = packs[:8]

        data[uid] = user
        self.save(data)

    def get_user_packs(self, user_id: int) -> list[dict[str, Any]]:
        data = self.load()
        user = self._get_user_data(data, user_id)
        packs = user.get("packs", [])
        if not isinstance(packs, list):
            return []
        out: list[dict[str, Any]] = []
        for item in packs:
            if not isinstance(item, dict):
                continue
            short_name = str(item.get("short_name") or "").strip()
            if not short_name:
                continue
            out.append(
                {
                    "short_name": short_name,
                    "title": str(item.get("title") or "").strip(),
                    "count": int(item.get("count", 0)),
                    "updated_at": str(item.get("updated_at") or ""),
                }
            )
        return out


class UsageStore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or Path(".usage_data.json")
        db_raw = os.getenv("BOT_SQLITE_PATH", "").strip()
        self.sqlite_path = Path(db_raw) if db_raw else None
        self.sqlite_key = "usage_data"

    def load(self) -> dict[str, Any]:
        if self.sqlite_path is not None:
            raw_db = _sqlite_get_json(self.sqlite_path, self.sqlite_key)
            if isinstance(raw_db, dict):
                if "policy" not in raw_db or not isinstance(raw_db.get("policy"), dict):
                    raw_db["policy"] = dict(DEFAULT_USAGE_POLICY)
                if "links" not in raw_db or not isinstance(raw_db.get("links"), dict):
                    raw_db["links"] = dict(DEFAULT_EXTERNAL_LINKS)
                if "users" not in raw_db or not isinstance(raw_db.get("users"), dict):
                    raw_db["users"] = {}
                return raw_db
        if not self.path.exists():
            return {
                "policy": dict(DEFAULT_USAGE_POLICY),
                "links": dict(DEFAULT_EXTERNAL_LINKS),
                "users": {},
            }
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return {
                "policy": dict(DEFAULT_USAGE_POLICY),
                "links": dict(DEFAULT_EXTERNAL_LINKS),
                "users": {},
            }
        if not isinstance(raw, dict):
            return {
                "policy": dict(DEFAULT_USAGE_POLICY),
                "links": dict(DEFAULT_EXTERNAL_LINKS),
                "users": {},
            }
        if "policy" not in raw or not isinstance(raw.get("policy"), dict):
            raw["policy"] = dict(DEFAULT_USAGE_POLICY)
        if "links" not in raw or not isinstance(raw.get("links"), dict):
            raw["links"] = dict(DEFAULT_EXTERNAL_LINKS)
        if "users" not in raw or not isinstance(raw.get("users"), dict):
            raw["users"] = {}
        if self.sqlite_path is not None:
            _sqlite_set_json(self.sqlite_path, self.sqlite_key, raw)
        return raw

    def save(self, data: dict[str, Any]) -> None:
        if self.sqlite_path is not None:
            _sqlite_set_json(self.sqlite_path, self.sqlite_key, data)
            return
        _atomic_write_json(self.path, data)

    def _policy_from_data(self, data: dict[str, Any]) -> dict[str, Any]:
        policy = dict(DEFAULT_USAGE_POLICY)
        raw = data.get("policy", {})
        for key in policy:
            if key not in raw:
                continue
            if key in {"enforce_limits", "daily_reset_enabled"}:
                policy[key] = bool(raw.get(key))
            else:
                try:
                    policy[key] = max(0, int(raw.get(key)))
                except (TypeError, ValueError):
                    continue
        return policy

    def get_policy(self) -> dict[str, Any]:
        return self._policy_from_data(self.load())

    def update_policy(self, updates: dict[str, Any]) -> dict[str, Any]:
        data = self.load()
        policy = self._policy_from_data(data)
        for key, val in updates.items():
            if key not in policy:
                continue
            if key in {"enforce_limits", "daily_reset_enabled"}:
                if isinstance(val, str):
                    policy[key] = val.strip().lower() in {"1", "true", "yes", "on"}
                else:
                    policy[key] = bool(val)
            else:
                policy[key] = max(0, int(val))
        data["policy"] = policy
        self.save(data)
        return policy

    def get_external_links(self) -> dict[str, str]:
        data = self.load()
        raw = data.get("links", {})
        out = dict(DEFAULT_EXTERNAL_LINKS)
        for key in out:
            out[key] = str(raw.get(key, "") or "").strip()
        return out

    def update_external_links(self, updates: dict[str, str]) -> dict[str, str]:
        data = self.load()
        raw_links = data.get("links", {})
        links = dict(DEFAULT_EXTERNAL_LINKS)
        for key in links:
            links[key] = str(raw_links.get(key, "") or "").strip()
        for key, val in updates.items():
            if key not in links:
                continue
            links[key] = str(val or "").strip()
        data["links"] = links
        self.save(data)
        return links

    def _now(self) -> str:
        return dt.datetime.now(dt.timezone.utc).isoformat()

    def _new_user(self, policy: dict[str, Any], username: str = "", display_name: str = "") -> dict[str, Any]:
        today = dt.datetime.now().date().isoformat()
        return {
            "clone_left": int(policy["free_clone"]),
            "make_left": int(policy["free_make"]),
            "invited_by": 0,
            "invite_count": 0,
            "username": username,
            "display_name": display_name,
            "recent_clone": [],
            "recent_make": [],
            "recent_invite": [],
            "created_at": self._now(),
            "updated_at": self._now(),
            "last_daily_grant_date": today,
            "clone_done_total": 0,
            "make_done_total": 0,
            "invite_reward_clone_total": 0,
            "invite_reward_make_total": 0,
        }

    def _apply_daily_grant(self, user: dict[str, Any], policy: dict[str, Any]) -> None:
        if not bool(policy.get("daily_reset_enabled", True)):
            return
        today = dt.datetime.now().date().isoformat()
        last_day = str(user.get("last_daily_grant_date") or "").strip()
        if last_day == today:
            return
        user["clone_left"] = max(int(user.get("clone_left", 0)), int(policy.get("daily_free_clone", 0)))
        user["make_left"] = max(int(user.get("make_left", 0)), int(policy.get("daily_free_make", 0)))
        user["last_daily_grant_date"] = today

    def _get_user(self, users: dict[str, Any], user_id: int, create_if_missing: bool, policy: dict[str, Any]) -> dict[str, Any]:
        key = str(user_id)
        item = users.get(key)
        if not isinstance(item, dict):
            item = None
        if item is None and create_if_missing:
            item = self._new_user(policy)
            users[key] = item
        if item is None:
            return {}
        return item

    def ensure_user(self, user_id: int, username: str = "", display_name: str = "") -> dict[str, Any]:
        data = self.load()
        policy = self._policy_from_data(data)
        users = data["users"]
        user = self._get_user(users, user_id, True, policy)
        self._apply_daily_grant(user, policy)
        if username:
            user["username"] = username
        if display_name:
            user["display_name"] = display_name
        user["updated_at"] = self._now()
        data["users"] = users
        self.save(data)
        return self.get_user_summary(user_id)

    def _push_recent(self, arr: list[Any], payload: dict[str, Any], cap: int = 8) -> list[dict[str, Any]]:
        out = [x for x in arr if isinstance(x, dict)]
        out.insert(0, payload)
        return out[:cap]

    def get_user_summary(self, user_id: int) -> dict[str, Any]:
        data = self.load()
        policy = self._policy_from_data(data)
        users = data["users"]
        user = self._get_user(users, user_id, True, policy)
        self._apply_daily_grant(user, policy)
        data["users"] = users
        self.save(data)
        return {
            "clone_left": int(user.get("clone_left", 0)),
            "make_left": int(user.get("make_left", 0)),
            "invite_count": int(user.get("invite_count", 0)),
            "invited_by": int(user.get("invited_by", 0)),
            "clone_done_total": int(user.get("clone_done_total", 0)),
            "make_done_total": int(user.get("make_done_total", 0)),
            "invite_reward_clone_total": int(user.get("invite_reward_clone_total", 0)),
            "invite_reward_make_total": int(user.get("invite_reward_make_total", 0)),
            "recent_clone": [x for x in user.get("recent_clone", []) if isinstance(x, dict)][:5],
            "recent_make": [x for x in user.get("recent_make", []) if isinstance(x, dict)][:5],
            "recent_invite": [x for x in user.get("recent_invite", []) if isinstance(x, dict)][:5],
            "username": str(user.get("username", "")),
            "display_name": str(user.get("display_name", "")),
            "last_daily_grant_date": str(user.get("last_daily_grant_date", "")),
            "policy": policy,
        }

    def consume(self, user_id: int, action: str) -> tuple[bool, int]:
        if action not in {"clone", "make"}:
            raise ValueError("无效操作类型")
        data = self.load()
        policy = self._policy_from_data(data)
        users = data["users"]
        user = self._get_user(users, user_id, True, policy)
        self._apply_daily_grant(user, policy)
        key = "clone_left" if action == "clone" else "make_left"
        left = int(user.get(key, 0))

        if (not policy.get("enforce_limits", True)) or left > 0:
            if policy.get("enforce_limits", True):
                user[key] = left - 1
            user["updated_at"] = self._now()
            data["users"] = users
            self.save(data)
            return True, int(user.get(key, left))

        return False, left

    def refund(self, user_id: int, action: str, amount: int = 1) -> int:
        if action not in {"clone", "make"}:
            raise ValueError("无效操作类型")
        data = self.load()
        policy = self._policy_from_data(data)
        users = data["users"]
        user = self._get_user(users, user_id, True, policy)
        key = "clone_left" if action == "clone" else "make_left"
        user[key] = int(user.get(key, 0)) + max(0, int(amount))
        user["updated_at"] = self._now()
        data["users"] = users
        self.save(data)
        return int(user[key])

    def set_user_quota(
        self,
        user_id: int,
        *,
        clone_left: int | None = None,
        make_left: int | None = None,
    ) -> dict[str, Any]:
        data = self.load()
        policy = self._policy_from_data(data)
        users = data["users"]
        user = self._get_user(users, user_id, True, policy)
        if clone_left is not None:
            user["clone_left"] = max(0, int(clone_left))
        if make_left is not None:
            user["make_left"] = max(0, int(make_left))
        user["updated_at"] = self._now()
        data["users"] = users
        self.save(data)
        return self.get_user_summary(user_id)

    def adjust_user_quota(
        self,
        user_id: int,
        *,
        clone_delta: int = 0,
        make_delta: int = 0,
    ) -> dict[str, Any]:
        data = self.load()
        policy = self._policy_from_data(data)
        users = data["users"]
        user = self._get_user(users, user_id, True, policy)
        if clone_delta:
            user["clone_left"] = max(0, int(user.get("clone_left", 0)) + int(clone_delta))
        if make_delta:
            user["make_left"] = max(0, int(user.get("make_left", 0)) + int(make_delta))
        user["updated_at"] = self._now()
        data["users"] = users
        self.save(data)
        return self.get_user_summary(user_id)

    def log_action(self, user_id: int, action: str, brief: str) -> None:
        if action not in {"clone", "make"}:
            raise ValueError("无效操作类型")
        data = self.load()
        policy = self._policy_from_data(data)
        users = data["users"]
        user = self._get_user(users, user_id, True, policy)
        payload = {"brief": brief, "at": self._now()}
        key = "recent_clone" if action == "clone" else "recent_make"
        user[key] = self._push_recent(user.get(key, []), payload)
        total_key = "clone_done_total" if action == "clone" else "make_done_total"
        user[total_key] = int(user.get(total_key, 0)) + 1
        user["updated_at"] = self._now()
        data["users"] = users
        self.save(data)

    def invite_link(self, bot_username: str, user_id: int) -> str:
        return f"https://t.me/{bot_username}?start=ref_{user_id}"

    def apply_referral(
        self,
        new_user_id: int,
        ref_code: str,
        *,
        new_username: str = "",
        new_display_name: str = "",
    ) -> tuple[bool, str, dict[str, int]]:
        if not ref_code:
            return False, "缺少邀请码。", {}
        m = re.match(r"^ref_(\d+)$", ref_code.strip())
        if not m:
            return False, "邀请码格式无效。", {}

        inviter_id = int(m.group(1))
        if inviter_id == new_user_id:
            return False, "不能邀请自己。", {}

        data = self.load()
        policy = self._policy_from_data(data)
        users = data["users"]
        new_user = self._get_user(users, new_user_id, True, policy)
        if new_username:
            new_user["username"] = new_username
        if new_display_name:
            new_user["display_name"] = new_display_name

        if int(new_user.get("invited_by", 0)) > 0:
            return False, "你已经绑定过邀请关系。", {}

        inviter = self._get_user(users, inviter_id, False, policy)
        if not inviter:
            return False, "邀请人不存在或尚未使用机器人。", {}

        reward_clone = int(policy["invite_reward_clone"])
        reward_make = int(policy["invite_reward_make"])
        inviter["clone_left"] = int(inviter.get("clone_left", 0)) + reward_clone
        inviter["make_left"] = int(inviter.get("make_left", 0)) + reward_make
        inviter["invite_reward_clone_total"] = int(inviter.get("invite_reward_clone_total", 0)) + reward_clone
        inviter["invite_reward_make_total"] = int(inviter.get("invite_reward_make_total", 0)) + reward_make
        inviter["invite_count"] = int(inviter.get("invite_count", 0)) + 1
        inviter["recent_invite"] = self._push_recent(
            inviter.get("recent_invite", []),
            {
                "uid": new_user_id,
                "username": new_user.get("username", ""),
                "display_name": new_user.get("display_name", ""),
                "reward_clone": reward_clone,
                "reward_make": reward_make,
                "at": self._now(),
            },
        )
        inviter["updated_at"] = self._now()

        new_user["invited_by"] = inviter_id
        new_user["updated_at"] = self._now()
        users[str(inviter_id)] = inviter
        users[str(new_user_id)] = new_user
        data["users"] = users
        self.save(data)
        return (
            True,
            f"邀请绑定成功，邀请人获得 clone+{reward_clone} / make+{reward_make} 次。",
            {
                "inviter_id": inviter_id,
                "reward_clone": reward_clone,
                "reward_make": reward_make,
            },
        )

    def list_users(self, page: int = 1, page_size: int = 20) -> dict[str, Any]:
        data = self.load()
        users = data.get("users", {})
        items: list[tuple[int, dict[str, Any]]] = []
        for k, v in users.items():
            if not isinstance(v, dict):
                continue
            try:
                uid = int(k)
            except ValueError:
                continue
            items.append((uid, v))
        items.sort(key=lambda kv: str(kv[1].get("updated_at", "")), reverse=True)

        page = max(1, int(page))
        page_size = max(1, min(100, int(page_size)))
        total = len(items)
        pages = max(1, (total + page_size - 1) // page_size)
        if page > pages:
            page = pages
        start = (page - 1) * page_size
        end = start + page_size
        sliced = items[start:end]

        out = []
        for uid, u in sliced:
            out.append(
                {
                    "user_id": uid,
                    "username": str(u.get("username", "")),
                    "display_name": str(u.get("display_name", "")),
                    "clone_left": int(u.get("clone_left", 0)),
                    "make_left": int(u.get("make_left", 0)),
                    "invite_count": int(u.get("invite_count", 0)),
                    "clone_done_total": int(u.get("clone_done_total", 0)),
                    "make_done_total": int(u.get("make_done_total", 0)),
                    "updated_at": str(u.get("updated_at", "")),
                }
            )

        return {
            "page": page,
            "page_size": page_size,
            "total": total,
            "pages": pages,
            "items": out,
        }

    def get_user_detail(self, user_id: int) -> dict[str, Any]:
        summary = self.get_user_summary(user_id)
        return summary

    def search_users(self, query: str, limit: int = 20) -> list[dict[str, Any]]:
        needle = (query or "").strip().lower()
        if not needle:
            return []

        data = self.load()
        users = data.get("users", {})
        out: list[dict[str, Any]] = []
        for k, u in users.items():
            if not isinstance(u, dict):
                continue
            try:
                uid = int(k)
            except ValueError:
                continue
            username = str(u.get("username", "") or "")
            display_name = str(u.get("display_name", "") or "")
            hay = " ".join([str(uid), username.lower(), display_name.lower()])
            if needle not in hay:
                continue
            out.append(
                {
                    "user_id": uid,
                    "username": username,
                    "display_name": display_name,
                    "clone_left": int(u.get("clone_left", 0)),
                    "make_left": int(u.get("make_left", 0)),
                    "invite_count": int(u.get("invite_count", 0)),
                    "clone_done_total": int(u.get("clone_done_total", 0)),
                    "make_done_total": int(u.get("make_done_total", 0)),
                    "updated_at": str(u.get("updated_at", "")),
                }
            )
        out.sort(key=lambda x: str(x.get("updated_at", "")), reverse=True)
        return out[: max(1, min(100, int(limit)))]

    def get_global_stats(self) -> dict[str, Any]:
        data = self.load()
        users = data.get("users", {})
        total_users = 0
        invited_users = 0
        total_clone_left = 0
        total_make_left = 0
        total_invites = 0
        total_clone_done = 0
        total_make_done = 0
        total_reward_clone = 0
        total_reward_make = 0

        for _, user in users.items():
            if not isinstance(user, dict):
                continue
            total_users += 1
            invited_users += 1 if int(user.get("invited_by", 0)) > 0 else 0
            total_clone_left += int(user.get("clone_left", 0))
            total_make_left += int(user.get("make_left", 0))
            total_invites += int(user.get("invite_count", 0))
            total_clone_done += int(user.get("clone_done_total", 0))
            total_make_done += int(user.get("make_done_total", 0))
            total_reward_clone += int(user.get("invite_reward_clone_total", 0))
            total_reward_make += int(user.get("invite_reward_make_total", 0))

        return {
            "policy": self._policy_from_data(data),
            "total_users": total_users,
            "invited_users": invited_users,
            "total_clone_left": total_clone_left,
            "total_make_left": total_make_left,
            "total_invites": total_invites,
            "total_clone_done": total_clone_done,
            "total_make_done": total_make_done,
            "total_reward_clone": total_reward_clone,
            "total_reward_make": total_reward_make,
        }

    def get_all_user_ids(self) -> list[int]:
        data = self.load()
        users = data.get("users", {})
        out: list[int] = []
        for k, _ in users.items():
            try:
                out.append(int(k))
            except (TypeError, ValueError):
                continue
        out.sort()
        return out

    def list_all_users(self) -> list[dict[str, Any]]:
        data = self.load()
        users = data.get("users", {})
        out: list[dict[str, Any]] = []
        for k, u in users.items():
            if not isinstance(u, dict):
                continue
            try:
                uid = int(k)
            except (TypeError, ValueError):
                continue
            out.append(
                {
                    "user_id": uid,
                    "username": str(u.get("username", "")),
                    "display_name": str(u.get("display_name", "")),
                    "clone_left": int(u.get("clone_left", 0)),
                    "make_left": int(u.get("make_left", 0)),
                    "invite_count": int(u.get("invite_count", 0)),
                    "invited_by": int(u.get("invited_by", 0)),
                    "clone_done_total": int(u.get("clone_done_total", 0)),
                    "make_done_total": int(u.get("make_done_total", 0)),
                    "updated_at": str(u.get("updated_at", "")),
                    "created_at": str(u.get("created_at", "")),
                }
            )
        out.sort(key=lambda x: str(x.get("updated_at", "")), reverse=True)
        return out


class AdminAuditStore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or Path(".admin_audit.jsonl")
        db_raw = os.getenv("BOT_SQLITE_PATH", "").strip()
        self.sqlite_path = Path(db_raw) if db_raw else None

    def _now(self) -> str:
        return dt.datetime.now(dt.timezone.utc).isoformat()

    def log(
        self,
        *,
        actor_user_id: int,
        action: str,
        detail: str,
        target_user_id: int | None = None,
        extra: dict[str, Any] | None = None,
    ) -> None:
        row: dict[str, Any] = {
            "at": self._now(),
            "actor_user_id": int(actor_user_id),
            "action": str(action or "").strip(),
            "detail": str(detail or "").strip(),
        }
        if target_user_id is not None:
            row["target_user_id"] = int(target_user_id)
        if extra and isinstance(extra, dict):
            row["extra"] = extra

        if self.sqlite_path is not None:
            _sqlite_init(self.sqlite_path)
            with sqlite3.connect(str(self.sqlite_path)) as conn:
                conn.execute(
                    "INSERT INTO audit_log(at, actor, action, detail, target, extra_json) VALUES(?, ?, ?, ?, ?, ?)",
                    (
                        str(row.get("at", "")),
                        int(row.get("actor_user_id", 0)),
                        str(row.get("action", "")),
                        str(row.get("detail", "")),
                        (int(row.get("target_user_id", 0)) if row.get("target_user_id") is not None else None),
                        (json.dumps(row.get("extra", {}), ensure_ascii=False) if row.get("extra") is not None else None),
                    ),
                )
                conn.commit()
            return

        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(row, ensure_ascii=False))
            f.write("\n")

    def recent(self, limit: int = 30) -> list[dict[str, Any]]:
        if limit <= 0:
            return []
        if self.sqlite_path is not None:
            _sqlite_init(self.sqlite_path)
            out: list[dict[str, Any]] = []
            with sqlite3.connect(str(self.sqlite_path)) as conn:
                rows = conn.execute(
                    "SELECT at, actor, action, detail, target, extra_json FROM audit_log ORDER BY id DESC LIMIT ?",
                    (max(1, min(200, int(limit))),),
                ).fetchall()
            for at, actor, action, detail, target, extra_json in rows:
                item: dict[str, Any] = {
                    "at": str(at or ""),
                    "actor_user_id": int(actor or 0),
                    "action": str(action or ""),
                    "detail": str(detail or ""),
                }
                if target is not None:
                    item["target_user_id"] = int(target)
                if extra_json:
                    try:
                        parsed = json.loads(str(extra_json))
                        if isinstance(parsed, dict):
                            item["extra"] = parsed
                    except json.JSONDecodeError:
                        pass
                out.append(item)
            return out
        if not self.path.exists():
            return []
        try:
            lines = self.path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return []
        out: list[dict[str, Any]] = []
        for line in reversed(lines):
            raw = line.strip()
            if not raw:
                continue
            try:
                item = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if not isinstance(item, dict):
                continue
            out.append(item)
            if len(out) >= limit:
                break
        return out


def extract_sticker_set_name(source: str) -> str:
    raw = source.strip().strip("<>").strip()
    if not raw:
        raise ValueError("来源为空")

    if raw.startswith("tg://"):
        parsed = urlparse(raw)
        query = parse_qs(parsed.query)
        if parsed.netloc in {"addstickers", "addemoji"}:
            set_name = (query.get("set") or [""])[0].strip()
            if set_name:
                return set_name
        raise ValueError(f"不支持的 tg 链接: {source}")

    web = re.search(
        r"(?:https?://)?(?:t|telegram)\.me/(?:addstickers|addemoji)/([A-Za-z0-9_]+)",
        raw,
        flags=re.IGNORECASE,
    )
    if web:
        return web.group(1)

    short = re.search(r"^([A-Za-z0-9_]{3,})$", raw)
    if short:
        return short.group(1)

    raise ValueError("无法解析来源，请使用表情包短名或 t.me/addstickers/<name> 链接。")


def default_clone_short_name(source_name: str) -> str:
    base = re.sub(r"_by_[A-Za-z0-9_]+$", "", source_name).strip("_")
    if not base:
        base = "pack"
    return f"{base}_clone"


def parse_emoji_list(raw: str | None, fallback: str = "😀") -> list[str]:
    if not raw:
        return [fallback]
    chunks = [x.strip() for x in re.split(r"[,\s]+", raw) if x.strip()]
    return chunks or [fallback]


def _load_font(size: int) -> ImageFont.ImageFont:
    candidates = ["arial.ttf", "seguiemj.ttf", "msyh.ttc", "simhei.ttf"]
    for candidate in candidates:
        try:
            return ImageFont.truetype(candidate, size=size)
        except OSError:
            continue
    return ImageFont.load_default()


def add_watermark(
    image: Image.Image,
    text: str,
    position: str = "br",
    opacity: int = 145,
) -> None:
    if not text:
        return

    draw = ImageDraw.Draw(image, "RGBA")
    width, height = image.size
    font_size = max(20, int(width * 0.08))
    font = _load_font(font_size)

    bbox = draw.textbbox((0, 0), text, font=font)
    text_w = bbox[2] - bbox[0]
    text_h = bbox[3] - bbox[1]

    margin = 14
    if position == "tl":
        x, y = margin, margin
    elif position == "tr":
        x, y = width - text_w - margin, margin
    elif position == "bl":
        x, y = margin, height - text_h - margin
    elif position == "c":
        x, y = (width - text_w) // 2, (height - text_h) // 2
    else:
        x, y = width - text_w - margin, height - text_h - margin

    alpha = max(0, min(opacity, 255))
    shadow_alpha = min(alpha + 60, 255)
    draw.text((x + 2, y + 2), text, font=font, fill=(0, 0, 0, shadow_alpha))
    draw.text((x, y), text, font=font, fill=(255, 255, 255, alpha))


def normalize_visual_mode(mode: str | None) -> str:
    candidate = (mode or "").strip().lower()
    if candidate in VISUAL_MODES:
        return candidate
    return "maker"


def normalize_fit_mode(mode: str | None) -> str:
    candidate = (mode or "").strip().lower()
    if candidate in FIT_MODES:
        return candidate
    return "contain"


def normalize_clone_mode(mode: str | None) -> str:
    candidate = (mode or "").strip().lower()
    if candidate in CLONE_MODES:
        return candidate
    return "studio"


def normalize_make_target_mode(mode: str | None) -> str:
    candidate = (mode or "").strip().lower()
    if candidate in MAKE_TARGET_MODE_LABELS:
        return candidate
    return "ask"


def visual_mode_label(mode: str | None) -> str:
    normalized = normalize_visual_mode(mode)
    return f"{VISUAL_MODE_LABELS.get(normalized, normalized)}({normalized})"


def fit_mode_label(mode: str | None) -> str:
    normalized = normalize_fit_mode(mode)
    return f"{FIT_MODE_LABELS.get(normalized, normalized)}({normalized})"


def clone_mode_label(mode: str | None) -> str:
    normalized = normalize_clone_mode(mode)
    return f"{CLONE_MODE_LABELS.get(normalized, normalized)}({normalized})"


def make_target_mode_label(mode: str | None) -> str:
    normalized = normalize_make_target_mode(mode)
    return f"{MAKE_TARGET_MODE_LABELS.get(normalized, normalized)}({normalized})"


def _fit_to_canvas(src: Image.Image, fit_mode: str) -> Image.Image:
    if fit_mode == "cover":
        return ImageOps.fit(src, STICKER_CANVAS, method=Image.Resampling.LANCZOS, centering=(0.5, 0.5))

    fitted = ImageOps.contain(src, STICKER_CANVAS, Image.Resampling.LANCZOS)
    canvas = Image.new("RGBA", STICKER_CANVAS, (0, 0, 0, 0))
    offset = (
        (STICKER_CANVAS[0] - fitted.size[0]) // 2,
        (STICKER_CANVAS[1] - fitted.size[1]) // 2,
    )
    canvas.paste(fitted, offset, fitted)
    return canvas


def _apply_visual_mode(canvas: Image.Image, mode: str) -> Image.Image:
    out = canvas
    if mode == "bw":
        out = ImageOps.grayscale(out).convert("RGBA")
    elif mode == "pixel":
        small = out.resize((96, 96), Image.Resampling.NEAREST)
        out = small.resize(STICKER_CANVAS, Image.Resampling.NEAREST)
    elif mode == "circle":
        mask = Image.new("L", STICKER_CANVAS, 0)
        draw = ImageDraw.Draw(mask)
        pad = 6
        draw.ellipse((pad, pad, STICKER_CANVAS[0] - pad, STICKER_CANVAS[1] - pad), fill=255)
        layer = Image.new("RGBA", STICKER_CANVAS, (0, 0, 0, 0))
        layer.paste(out, (0, 0), mask)
        out = layer
    elif mode == "brand":
        draw = ImageDraw.Draw(out, "RGBA")
        bar_h = 82
        draw.rectangle(
            (0, STICKER_CANVAS[1] - bar_h, STICKER_CANVAS[0], STICKER_CANVAS[1]),
            fill=(0, 0, 0, 100),
        )
    return out


def render_static_sticker(
    data: bytes,
    watermark: str | None,
    wm_pos: str,
    wm_opacity: int,
    *,
    mode: str = "maker",
    fit_mode: str = "contain",
) -> bytes:
    src = Image.open(io.BytesIO(data))
    src = ImageOps.exif_transpose(src).convert("RGBA")
    norm_mode = normalize_visual_mode(mode)
    norm_fit = normalize_fit_mode(fit_mode)

    canvas = _fit_to_canvas(src, norm_fit)
    canvas = _apply_visual_mode(canvas, norm_mode)

    if watermark:
        wm_position = "br" if norm_mode == "brand" else wm_pos
        wm_alpha = min(255, wm_opacity + 20) if norm_mode == "brand" else wm_opacity
        add_watermark(canvas, watermark, position=wm_position, opacity=wm_alpha)

    quality_steps = [96, 92, 88, 84, 80, 76, 72]
    for quality in quality_steps:
        buff = io.BytesIO()
        canvas.save(
            buff,
            format="WEBP",
            quality=quality,
            method=6,
        )
        out = buff.getvalue()
        if len(out) <= MAX_STICKER_SIZE:
            return out

    raise ValueError("贴纸压缩后仍过大，请换更简单或细节更少的图片")


def detect_sticker_format(sticker: dict[str, Any]) -> str:
    if sticker.get("is_animated"):
        return "animated"
    if sticker.get("is_video"):
        return "video"
    return "static"


def normalize_short_name(name: str, bot_username: str) -> str:
    short = re.sub(r"[^a-z0-9_]", "_", name.lower()).strip("_")
    if not short:
        raise ValueError("短名不合法")

    suffix = f"_by_{bot_username.lower()}"
    short = re.sub(r"_by_[a-z0-9_]+$", "", short)
    max_base_len = 64 - len(suffix)
    if max_base_len <= 0:
        raise ValueError("机器人用户名过长")

    short = short[:max_base_len].rstrip("_")
    if not short:
        short = "pack"

    return f"{short}{suffix}"


def build_input_sticker(
    file_ref: str,
    emojis: list[str],
    keywords: str | None = None,
    *,
    sticker_format: str | None = None,
) -> dict[str, Any]:
    item: dict[str, Any] = {
        "sticker": file_ref,
        "emoji_list": emojis,
    }
    if sticker_format:
        item["format"] = sticker_format
    if keywords:
        item["keywords"] = [x.strip() for x in keywords.split(",") if x.strip()]
    return item


def load_emoji_map(path: Path | None) -> dict[str, str]:
    mapping: dict[str, str] = {}
    if not path:
        return mapping

    with path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        if "filename" not in reader.fieldnames or "emoji" not in reader.fieldnames:
            raise ValueError("emoji 映射 CSV 必须包含表头: filename,emoji")
        for row in reader:
            filename = (row.get("filename") or "").strip()
            emoji = (row.get("emoji") or "").strip()
            if filename and emoji:
                mapping[filename] = emoji
    return mapping


def _extract_user_from_update(update: dict[str, Any]) -> dict[str, Any] | None:
    if "message" in update:
        return update["message"].get("from")
    if "edited_message" in update:
        return update["edited_message"].get("from")
    if "callback_query" in update:
        return update["callback_query"].get("from")
    return None


async def get_recent_users(client: TelegramBotClient) -> list[dict[str, Any]]:
    updates = await client.call("getUpdates", {"limit": 100})
    seen: set[int] = set()
    users: list[dict[str, Any]] = []

    for update in reversed(updates):
        candidate = _extract_user_from_update(update)
        if not candidate or candidate.get("is_bot") or not candidate.get("id"):
            continue

        uid = int(candidate["id"])
        if uid in seen:
            continue

        seen.add(uid)
        users.append(
            {
                "id": uid,
                "username": candidate.get("username", ""),
                "name": (
                    f"{candidate.get('first_name', '')} {candidate.get('last_name', '')}".strip()
                ),
            }
        )

    return users


async def resolve_owner_user_id(client: TelegramBotClient, explicit: int | None) -> int:
    if explicit:
        return explicit

    users = await get_recent_users(client)
    if not users:
        raise ValueError("无法自动识别所属用户ID，请先给机器人发一条消息。")

    top = users[0]
    console.print(
        f"自动识别所属用户ID: {top['id']} (用户名: {top['username'] or '无'})",
        style="cyan",
    )
    return int(top["id"])


async def cmd_whoami(client: TelegramBotClient) -> None:
    users = await get_recent_users(client)

    if not users:
        console.print("未找到用户更新，请先给机器人发一条消息。", style="yellow")
        return

    table = Table(title="最近与机器人互动的用户")
    table.add_column("user_id")
    table.add_column("username")
    table.add_column("name")

    for info in users:
        table.add_row(str(info["id"]), info["username"], info["name"])

    console.print(table)


async def _maybe_await(value: Any) -> None:
    if inspect.isawaitable(value):
        await value


async def clone_sticker_set(
    client: TelegramBotClient,
    *,
    source_input: str,
    owner_user_id: int,
    bot_username: str,
    new_short_name: str | None = None,
    new_title: str | None = None,
    watermark: str | None = None,
    watermark_pos: str = "br",
    watermark_opacity: int = 145,
    visual_mode: str = "maker",
    fit_mode: str = "contain",
    clone_mode: str = "studio",
    progress_cb: Any | None = None,
    info_cb: Any | None = None,
) -> dict[str, Any]:
    source_name = extract_sticker_set_name(source_input)
    source = await client.call("getStickerSet", {"name": source_name})
    source_stickers: list[dict[str, Any]] = source.get("stickers", [])
    if not source_stickers:
        raise ValueError("来源表情包为空")

    final_title = new_title or f"{source.get('title', source_name)} 克隆"
    short_base = new_short_name or default_clone_short_name(source_name)
    target_short_name = normalize_short_name(short_base, bot_username)

    sticker_type = source.get("sticker_type", "regular")
    sticker_format = detect_sticker_format(source_stickers[0])
    norm_visual_mode = normalize_visual_mode(visual_mode)
    norm_fit_mode = normalize_fit_mode(fit_mode)
    norm_clone_mode = normalize_clone_mode(clone_mode)

    if watermark and sticker_format != "static" and info_cb is not None:
        await _maybe_await(
            info_cb("署名仅对静态贴纸生效，动画/视频贴纸将按原样复制。")
        )

    state = StateStore(target_short_name)
    state_obj = state.load()
    done: set[str] = set(state_obj.get("done", []))
    created = bool(state_obj.get("created", False))
    total = len(source_stickers)

    def should_render_static(fmt: str) -> bool:
        if fmt != "static":
            return False
        if norm_clone_mode != "copy":
            return True
        if watermark:
            return True
        return False

    def is_sticker_format_error(exc: Exception) -> bool:
        return "sticker format must be non-empty" in str(exc).lower()

    if (
        norm_clone_mode == "copy"
        and watermark
        and info_cb is not None
    ):
        await _maybe_await(info_cb("clone_mode=copy + watermark: 静态贴纸将渲染后再入包。"))

    async def create_set_with(sticker: dict[str, Any], emojis: list[str]) -> None:
        nonlocal created
        fmt = detect_sticker_format(sticker)

        if should_render_static(fmt):
            raw = await client.download_file(sticker["file_id"])
            out = render_static_sticker(
                raw,
                watermark=watermark,
                wm_pos=watermark_pos,
                wm_opacity=watermark_opacity,
                mode=norm_visual_mode,
                fit_mode=norm_fit_mode,
            )
            payload = {
                "user_id": owner_user_id,
                "name": target_short_name,
                "title": final_title,
                "sticker_type": sticker_type,
                "sticker_format": "static",
                "stickers": json.dumps(
                    [build_input_sticker("attach://sticker_file", emojis, sticker_format="static")],
                    ensure_ascii=False,
                ),
            }
            files = {"sticker_file": ("sticker.webp", out, "image/webp")}
            await client.call("createNewStickerSet", payload, files=files)
        else:
            payload = {
                "user_id": owner_user_id,
                "name": target_short_name,
                "title": final_title,
                "sticker_type": sticker_type,
                "sticker_format": fmt,
                "stickers": [build_input_sticker(sticker["file_id"], emojis, sticker_format=fmt)],
            }
            try:
                await client.call("createNewStickerSet", payload)
            except TelegramAPIError as exc:
                # Some static packs still fail in pure copy mode; fallback to upload rendered static sticker.
                if fmt != "static" or (not is_sticker_format_error(exc)):
                    raise
                raw = await client.download_file(sticker["file_id"])
                out = render_static_sticker(
                    raw,
                    watermark=watermark,
                    wm_pos=watermark_pos,
                    wm_opacity=watermark_opacity,
                    mode=norm_visual_mode,
                    fit_mode=norm_fit_mode,
                )
                fallback_payload = {
                    "user_id": owner_user_id,
                    "name": target_short_name,
                    "title": final_title,
                    "sticker_type": sticker_type,
                    "sticker_format": "static",
                    "stickers": json.dumps(
                        [build_input_sticker("attach://sticker_file", emojis, sticker_format="static")],
                        ensure_ascii=False,
                    ),
                }
                files = {"sticker_file": ("sticker.webp", out, "image/webp")}
                await client.call("createNewStickerSet", fallback_payload, files=files)

        created = True
        state_obj["created"] = True
        state.save(state_obj)

    async def add_one(sticker: dict[str, Any], emojis: list[str]) -> None:
        fmt = detect_sticker_format(sticker)

        if should_render_static(fmt):
            raw = await client.download_file(sticker["file_id"])
            out = render_static_sticker(
                raw,
                watermark=watermark,
                wm_pos=watermark_pos,
                wm_opacity=watermark_opacity,
                mode=norm_visual_mode,
                fit_mode=norm_fit_mode,
            )
            payload = {
                "user_id": owner_user_id,
                "name": target_short_name,
                "sticker": json.dumps(
                    build_input_sticker("attach://sticker_file", emojis, sticker_format="static"),
                    ensure_ascii=False,
                ),
            }
            files = {"sticker_file": ("sticker.webp", out, "image/webp")}
            await client.call("addStickerToSet", payload, files=files)
        else:
            payload = {
                "user_id": owner_user_id,
                "name": target_short_name,
                "sticker": build_input_sticker(sticker["file_id"], emojis, sticker_format=fmt),
            }
            try:
                await client.call("addStickerToSet", payload)
            except TelegramAPIError as exc:
                if fmt != "static" or (not is_sticker_format_error(exc)):
                    raise
                raw = await client.download_file(sticker["file_id"])
                out = render_static_sticker(
                    raw,
                    watermark=watermark,
                    wm_pos=watermark_pos,
                    wm_opacity=watermark_opacity,
                    mode=norm_visual_mode,
                    fit_mode=norm_fit_mode,
                )
                fallback_payload = {
                    "user_id": owner_user_id,
                    "name": target_short_name,
                    "sticker": json.dumps(
                        build_input_sticker("attach://sticker_file", emojis, sticker_format="static"),
                        ensure_ascii=False,
                    ),
                }
                files = {"sticker_file": ("sticker.webp", out, "image/webp")}
                await client.call("addStickerToSet", fallback_payload, files=files)

    completed_count = len(done)
    if progress_cb is not None:
        await _maybe_await(progress_cb(completed_count, total))

    for i, sticker in enumerate(source_stickers):
        key = sticker.get("file_unique_id") or f"idx-{i}"
        if key in done:
            continue

        emojis = parse_emoji_list(sticker.get("emoji"), fallback="😀")
        if not created:
            await create_set_with(sticker, emojis)
        else:
            await add_one(sticker, emojis)

        done.add(key)
        state_obj["done"] = sorted(done)
        state.save(state_obj)
        completed_count = len(done)
        if progress_cb is not None:
            await _maybe_await(progress_cb(completed_count, total))

    return {
        "source_name": source_name,
        "source_count": total,
        "target_short_name": target_short_name,
        "target_title": final_title,
        "owner_user_id": owner_user_id,
        "visual_mode": norm_visual_mode,
        "fit_mode": norm_fit_mode,
        "clone_mode": norm_clone_mode,
    }


async def extract_image_bytes_from_message(
    client: TelegramBotClient,
    message: dict[str, Any],
) -> bytes | None:
    photos = message.get("photo") or []
    if photos:
        best = max(
            photos,
            key=lambda p: (int(p.get("file_size", 0)), int(p.get("width", 0)) * int(p.get("height", 0))),
        )
        return await client.download_file(best["file_id"])

    doc = message.get("document")
    if not doc:
        return None

    mime = (doc.get("mime_type") or "").lower()
    filename = (doc.get("file_name") or "").lower()
    ext_ok = any(filename.endswith(sfx) for sfx in STATIC_SUFFIXES)
    mime_ok = mime.startswith("image/")
    if not (ext_ok or mime_ok):
        return None

    return await client.download_file(doc["file_id"])


async def create_or_add_single_sticker(
    client: TelegramBotClient,
    *,
    owner_user_id: int,
    bot_username: str,
    image_bytes: bytes,
    emoji_text: str | None = None,
    pack_short_name: str | None = None,
    pack_title: str | None = None,
    watermark: str | None = None,
    watermark_pos: str = "br",
    watermark_opacity: int = 145,
    visual_mode: str = "maker",
    fit_mode: str = "contain",
    force_new_pack: bool = False,
) -> dict[str, Any]:
    now_ms = int(time.time() * 1000)
    short_base = pack_short_name or (f"u{owner_user_id}_auto_{now_ms}" if force_new_pack else f"u{owner_user_id}_auto")
    target_short_name = normalize_short_name(short_base, bot_username)
    target_title = (pack_title or f"{owner_user_id} 自动包").strip()
    emoji_list = parse_emoji_list(emoji_text, fallback="😀")

    out = render_static_sticker(
        image_bytes,
        watermark=watermark,
        wm_pos=watermark_pos,
        wm_opacity=watermark_opacity,
        mode=visual_mode,
        fit_mode=fit_mode,
    )
    upload = {"sticker_file": ("sticker.webp", out, "image/webp")}
    input_sticker = build_input_sticker("attach://sticker_file", emoji_list, sticker_format="static")

    def _is_set_not_found_error(exc: Exception) -> bool:
        lower_err = str(exc).lower()
        return "stickerset_invalid" in lower_err or "sticker set name is invalid" in lower_err

    def _is_too_much_error(exc: Exception) -> bool:
        return "stickers_too_much" in str(exc).lower()

    def _is_short_occupied(exc: Exception) -> bool:
        lower_err = str(exc).lower()
        return "short_name_occupied" in lower_err or "sticker set name is already occupied" in lower_err

    async def _create_new_set(short_name: str, title: str) -> None:
        payload = {
            "user_id": owner_user_id,
            "name": short_name,
            "title": title,
            "sticker_type": "regular",
            "sticker_format": "static",
            "stickers": json.dumps([input_sticker], ensure_ascii=False),
        }
        await client.call("createNewStickerSet", payload, files=upload)

    async def _create_overflow_set(base_short_name: str, base_title: str) -> tuple[str, str]:
        stem = re.sub(r"_by_[a-z0-9_]+$", "", base_short_name.lower()).strip("_")
        if not stem:
            stem = f"u{owner_user_id}_auto"
        for idx in range(2, 20):
            candidate_short = normalize_short_name(f"{stem}_p{idx}", bot_username)
            candidate_title = f"{base_title} {idx}"
            if len(candidate_title) > 64:
                candidate_title = candidate_title[:64].rstrip()
            try:
                await _create_new_set(candidate_short, candidate_title)
                return candidate_short, candidate_title
            except TelegramAPIError as exc:
                if _is_short_occupied(exc):
                    continue
                raise
        raise ValueError("当前包已满，且自动创建新分包失败，请稍后重试。")

    exists = False
    set_size = 0
    try:
        if not force_new_pack:
            set_info = await client.call("getStickerSet", {"name": target_short_name})
            stickers = set_info.get("stickers", []) if isinstance(set_info, dict) else []
            if isinstance(stickers, list):
                set_size = len(stickers)
            exists = True
    except TelegramAPIError as exc:
        if not _is_set_not_found_error(exc):
            raise

    if exists:
        if set_size >= 120:
            new_short, new_title = await _create_overflow_set(target_short_name, target_title)
            target_short_name = new_short
            target_title = new_title
            action = "created_overflow"
            return {
                "action": action,
                "target_short_name": target_short_name,
                "target_title": target_title,
                "visual_mode": normalize_visual_mode(visual_mode),
                "fit_mode": normalize_fit_mode(fit_mode),
            }
        payload = {
            "user_id": owner_user_id,
            "name": target_short_name,
            "sticker": json.dumps(input_sticker, ensure_ascii=False),
        }
        try:
            await client.call("addStickerToSet", payload, files=upload)
            action = "added"
        except TelegramAPIError as exc:
            if not _is_too_much_error(exc):
                raise
            new_short, new_title = await _create_overflow_set(target_short_name, target_title)
            target_short_name = new_short
            target_title = new_title
            action = "created_overflow"
    else:
        await _create_new_set(target_short_name, target_title)
        action = "created"

    return {
        "action": action,
        "target_short_name": target_short_name,
        "target_title": target_title,
        "visual_mode": normalize_visual_mode(visual_mode),
        "fit_mode": normalize_fit_mode(fit_mode),
    }


async def cmd_clone(client: TelegramBotClient, args: argparse.Namespace) -> None:
    me = await client.call("getMe")
    bot_username = me["username"]
    owner_user_id = await resolve_owner_user_id(client, args.owner_user_id)

    source_input = args.source or args.source_name
    if not source_input:
        raise ValueError("缺少来源，请使用 --source 或 --source-name")

    result = await clone_sticker_set(
        client,
        source_input=source_input,
        owner_user_id=owner_user_id,
        bot_username=bot_username,
        new_short_name=args.new_short_name,
        new_title=args.new_title,
        watermark=args.watermark,
        watermark_pos=args.watermark_pos,
        watermark_opacity=args.watermark_opacity,
        visual_mode=args.mode,
        fit_mode=args.fit_mode,
        clone_mode=args.clone_mode,
        progress_cb=lambda done, total: console.print(f"[{done}/{total}] 完成"),
        info_cb=lambda msg: console.print(msg, style="yellow"),
    )

    console.print(f"来源贴纸数: {result['source_count']}")
    console.print(f"来源包短名: {result['source_name']}")
    console.print(f"目标标题: {result['target_title']}")
    console.print(f"目标短名: {result['target_short_name']}")
    console.print(f"所属用户ID: {result['owner_user_id']}")
    console.print(f"克隆策略: {result['clone_mode']}，视觉模式: {result['visual_mode']}，适配: {result['fit_mode']}")
    console.print(
        f"完成，打开: https://t.me/addstickers/{result['target_short_name']}",
        style="green",
    )


async def cmd_create(client: TelegramBotClient, args: argparse.Namespace) -> None:
    me = await client.call("getMe")
    bot_username = me["username"]
    owner_user_id = await resolve_owner_user_id(client, args.owner_user_id)
    target_short_name = normalize_short_name(args.new_short_name, bot_username)

    assets_dir = Path(args.assets_dir)
    if not assets_dir.exists():
        raise ValueError(f"素材目录不存在: {assets_dir}")

    files = sorted(
        [
            p
            for p in assets_dir.iterdir()
            if p.is_file() and p.suffix.lower() in STATIC_SUFFIXES
        ],
        key=lambda p: p.name.lower(),
    )

    if not files:
        raise ValueError("未找到可用素材（仅支持 .png/.jpg/.jpeg/.webp）")

    emoji_map = load_emoji_map(Path(args.emoji_map) if args.emoji_map else None)

    state = StateStore(target_short_name)
    state_obj = state.load()
    done: set[str] = set(state_obj.get("done", []))
    created = bool(state_obj.get("created", False))

    default_emoji_list = parse_emoji_list(args.default_emoji, fallback="😀")

    async def create_with_file(path: Path, emojis: list[str]) -> None:
        nonlocal created
        data = path.read_bytes()
        out = render_static_sticker(
            data,
            watermark=args.watermark,
            wm_pos=args.watermark_pos,
            wm_opacity=args.watermark_opacity,
            mode=args.mode,
            fit_mode=args.fit_mode,
        )

        payload = {
            "user_id": owner_user_id,
            "name": target_short_name,
            "title": args.new_title,
            "sticker_type": "regular",
            "sticker_format": "static",
            "stickers": json.dumps(
                [build_input_sticker("attach://sticker_file", emojis, sticker_format="static")],
                ensure_ascii=False,
            ),
        }
        upload = {"sticker_file": (f"{path.stem}.webp", out, "image/webp")}
        await client.call("createNewStickerSet", payload, files=upload)

        created = True
        state_obj["created"] = True
        state.save(state_obj)

    async def add_file(path: Path, emojis: list[str]) -> None:
        data = path.read_bytes()
        out = render_static_sticker(
            data,
            watermark=args.watermark,
            wm_pos=args.watermark_pos,
            wm_opacity=args.watermark_opacity,
            mode=args.mode,
            fit_mode=args.fit_mode,
        )

        payload = {
            "user_id": owner_user_id,
            "name": target_short_name,
            "sticker": json.dumps(
                build_input_sticker("attach://sticker_file", emojis, sticker_format="static"),
                ensure_ascii=False,
            ),
        }
        upload = {"sticker_file": (f"{path.stem}.webp", out, "image/webp")}
        await client.call("addStickerToSet", payload, files=upload)

    for i, path in enumerate(files):
        key = path.name
        if key in done:
            continue

        emoji_raw = emoji_map.get(path.name)
        emojis = parse_emoji_list(emoji_raw, fallback=default_emoji_list[0])

        if not created:
            await create_with_file(path, emojis)
        else:
            await add_file(path, emojis)

        done.add(key)
        state_obj["done"] = sorted(done)
        state.save(state_obj)
        console.print(f"[{i + 1}/{len(files)}] 完成: {path.name}")

    console.print(f"风格模式: {normalize_visual_mode(args.mode)}，适配模式: {normalize_fit_mode(args.fit_mode)}")
    console.print(f"完成，打开: https://t.me/addstickers/{target_short_name}", style="green")


async def cmd_wizard(client: TelegramBotClient) -> None:
    console.print("Telegram 表情包工作室 向导模式", style="bold cyan")
    console.print("1) 查看最近用户ID (whoami)")
    console.print("2) 一键克隆表情包 (clone)")
    console.print("3) 本地素材创建表情包 (create)")
    console.print("4) 启动机器人服务 (serve)")

    choice = input("请选择 [1/2/3/4]: ").strip()
    if choice == "1":
        await cmd_whoami(client)
        return

    if choice == "2":
        source = input("粘贴来源（短名或链接）: ").strip()
        new_title = input("新标题（回车自动）: ").strip() or None
        new_short_name = input("新短名（回车自动）: ").strip() or None
        owner_raw = input("所属用户ID（回车自动识别）: ").strip()
        watermark = input("水印文本（回车不加）: ").strip() or None

        owner_user_id = int(owner_raw) if owner_raw else None
        args = argparse.Namespace(
            source=source,
            source_name=None,
            new_short_name=new_short_name,
            new_title=new_title,
            owner_user_id=owner_user_id,
            watermark=watermark,
            watermark_pos="br",
            watermark_opacity=145,
            mode="maker",
            fit_mode="contain",
            clone_mode="studio",
        )
        await cmd_clone(client, args)
        return

    if choice == "3":
        assets_dir = input("素材目录（例如 assets）: ").strip()
        new_title = input("新标题: ").strip()
        new_short_name = input("新短名: ").strip()
        owner_raw = input("所属用户ID（回车自动识别）: ").strip()
        default_emoji = input("默认 emoji（回车用 😀）: ").strip() or "😀"
        emoji_map = input("emoji 映射文件路径（回车跳过）: ").strip() or None
        watermark = input("水印文本（回车不加）: ").strip() or None

        owner_user_id = int(owner_raw) if owner_raw else None
        args = argparse.Namespace(
            assets_dir=assets_dir,
            new_short_name=new_short_name,
            new_title=new_title,
            owner_user_id=owner_user_id,
            default_emoji=default_emoji,
            emoji_map=emoji_map,
            watermark=watermark,
            watermark_pos="br",
            watermark_opacity=145,
            mode="maker",
            fit_mode="contain",
        )
        await cmd_create(client, args)
        return

    if choice == "4":
        args = argparse.Namespace(
            poll_timeout=40,
            max_jobs=3,
            progress_step=5,
            serve_mode="poll",
            webhook_url=None,
            webhook_path="/telegram/webhook",
            webhook_host="0.0.0.0",
            webhook_port=8080,
            webhook_secret=None,
        )
        await cmd_serve(client, args)
        return

    raise ValueError("无效选择，请输入 1/2/3/4")


def parse_command(text: str) -> tuple[str, str] | tuple[None, None]:
    msg = text.strip()
    if not msg.startswith("/"):
        return None, None
    first, *rest = msg.split(maxsplit=1)
    command = first[1:].split("@", 1)[0].lower()
    payload = rest[0].strip() if rest else ""
    return command, payload


def parse_make_payload(payload: str) -> dict[str, str | None]:
    raw = payload.strip()
    emoji: str | None = None
    title: str | None = None
    short_name: str | None = None
    watermark: str | None = None
    mode: str | None = None
    fit_mode: str | None = None

    if not raw:
        return {
            "emoji": None,
            "title": None,
            "short_name": None,
            "watermark": None,
            "mode": None,
            "fit_mode": None,
        }

    if "|" in raw:
        parts = [x.strip() for x in raw.split("|")]
        if len(parts) > 0 and parts[0]:
            emoji = parts[0]
        if len(parts) > 1 and parts[1]:
            title = parts[1]
        if len(parts) > 2 and parts[2]:
            short_name = parts[2]
        if len(parts) > 3 and parts[3]:
            watermark = parts[3]
        if len(parts) > 4 and parts[4]:
            mode = parts[4]
        if len(parts) > 5 and parts[5]:
            fit_mode = parts[5]
    else:
        tokens = [x.strip() for x in raw.split() if x.strip()]
        for i, token in enumerate(tokens):
            if "=" not in token:
                if i == 0 and emoji is None:
                    emoji = token
                continue
            key, val = token.split("=", 1)
            k = key.lower().strip()
            v = val.strip()
            if not v:
                continue
            if k in {"wm", "watermark", "maker", "sign", "signature"}:
                watermark = v
            elif k in {"title", "name"}:
                title = v
            elif k in {"short", "short_name", "pack"}:
                short_name = v
            elif k in {"emoji", "e"}:
                emoji = v
            elif k in {"mode", "style"}:
                mode = v
            elif k in {"fit", "fit_mode"}:
                fit_mode = v

    return {
        "emoji": emoji,
        "title": title,
        "short_name": short_name,
        "watermark": watermark,
        "mode": mode,
        "fit_mode": fit_mode,
    }


def parse_clone_payload(payload: str) -> dict[str, str | None]:
    raw = payload.strip()
    if not raw:
        raise ValueError("请提供表情包链接或短名。")

    source = ""
    watermark: str | None = None
    new_title: str | None = None
    new_short_name: str | None = None
    mode: str | None = None
    fit_mode: str | None = None
    clone_mode: str | None = None

    if "|" in raw:
        parts = [x.strip() for x in raw.split("|")]
        source = parts[0] if parts else ""
        if len(parts) > 1 and parts[1]:
            watermark = parts[1]
        if len(parts) > 2 and parts[2]:
            new_title = parts[2]
        if len(parts) > 3 and parts[3]:
            new_short_name = parts[3]
        if len(parts) > 4 and parts[4]:
            mode = parts[4]
        if len(parts) > 5 and parts[5]:
            fit_mode = parts[5]
        if len(parts) > 6 and parts[6]:
            clone_mode = parts[6]
    else:
        lines = [x.strip() for x in raw.splitlines() if x.strip()]
        if not lines:
            raise ValueError("请提供有效输入。")

        first_line_parts = lines[0].split()
        source = first_line_parts[0]
        for token in first_line_parts[1:]:
            if "=" not in token:
                continue
            key, val = token.split("=", 1)
            k = key.lower().strip()
            v = val.strip()
            if not v:
                continue
            if k in {"wm", "watermark", "maker", "sign", "signature"}:
                watermark = v
            elif k == "title":
                new_title = v
            elif k in {"short", "short_name"}:
                new_short_name = v
            elif k in {"mode", "style"}:
                mode = v
            elif k in {"fit", "fit_mode"}:
                fit_mode = v
            elif k in {"clone", "clone_mode"}:
                clone_mode = v

        for line in lines[1:]:
            m = re.match(
                r"^(wm|watermark|maker|sign|signature|title|short|short_name|mode|style|fit|fit_mode|clone|clone_mode)\s*=\s*(.+)$",
                line,
                flags=re.IGNORECASE,
            )
            if not m:
                continue
            key = m.group(1).lower()
            val = m.group(2).strip()
            if key in {"wm", "watermark", "maker", "sign", "signature"}:
                watermark = val
            elif key == "title":
                new_title = val
            elif key in {"short", "short_name"}:
                new_short_name = val
            elif key in {"mode", "style"}:
                mode = val
            elif key in {"fit", "fit_mode"}:
                fit_mode = val
            elif key in {"clone", "clone_mode"}:
                clone_mode = val

    return {
        "source": source.strip(),
        "watermark": watermark,
        "new_title": new_title,
        "new_short_name": new_short_name,
        "mode": mode,
        "fit_mode": fit_mode,
        "clone_mode": clone_mode,
    }


def parse_settitle_payload(payload: str) -> tuple[str | None, str]:
    raw = (payload or "").strip()
    if not raw:
        raise ValueError("请提供标题。")
    if "|" in raw:
        parts = [x.strip() for x in raw.split("|", 1)]
        source = parts[0] if parts else ""
        title = parts[1] if len(parts) > 1 else ""
        if not title:
            raise ValueError("请在 | 后填写标题。")
        short_name = extract_sticker_set_name(source) if source else None
        return short_name, title
    return None, raw


def serve_welcome_text(bot_username: str) -> str:
    return (
        "一款优雅且的Telegram贴纸/表情克隆工具，支持贴纸包高效处理、表情包克隆，一键跳转，极简操作！\n"
        "演示机器人 @bahaohuanhuibot\n\n"
        "新手三步:\n"
        "1) 发表情包链接 -> 自动克隆\n"
        "2) 发图片 -> 自动做成贴纸并加入当前包\n"
        "3) 进个人中心 -> 查看额度、最近记录、切换设置\n\n"
        "常用入口: /menu 或 /center\n"
        "需要完整命令: /helpall\n"
        f"机器人: @{bot_username}"
    )


def serve_help_text(bot_username: str) -> str:
    return (
        "快速帮助（简版）\n\n"
        "1) 克隆: 直接发 https://t.me/addstickers/xxxx\n"
        "2) 制作: 直接发图片（可选加入当前包/新建包）\n"
        "3) 菜单: /menu 或 /center\n"
        "4) 邀请: /invite\n"
        "5) 额度: /quota\n\n"
        "常用设置:\n"
        "/setmaker @你的署名\n"
        "/setmode maker\n"
        "/setfit contain\n"
        "/setmaketarget ask\n"
        "/settitle 新标题（修改当前包标题）\n\n"
        "查看完整命令: /helpall\n"
        f"机器人: @{bot_username}"
    )


def serve_help_full_text(bot_username: str) -> str:
    return (
        "贴一个表情包链接即可自动克隆（小白也会用）。\n\n"
        "快速用法:\n"
        "1) 直接发: https://t.me/addstickers/xxxx\n"
        "2) 或用命令: /clone <链接或短名>\n\n"
        "图片制作为贴纸:\n"
        "1) 直接发图片（可选加入当前包或新建包）\n"
        "2) 图片标题写: /make 😀 | 包标题 | 包短名 | 署名 | mode | fit\n\n"
        "高级参数:\n"
        "/clone <source> | <watermark> | <new_title> | <new_short_name> | mode | fit | clone_mode\n\n"
        "示例:\n"
        "/clone https://t.me/addstickers/OldPack | @mybrand | My Clone Pack | brand | contain | studio\n\n"
        "其他命令:\n"
        "/setwm @mybrand  设置默认水印\n"
        "/setmaker @mybrand  设置默认制作人署名(同 /setwm)\n"
        "/clearwm         清空默认水印\n"
        "/clearmaker      清空默认制作人署名(同 /clearwm)\n"
        "/setmode <maker|clean|brand|circle|pixel|bw>\n"
        "/setfit <contain|cover>\n"
        "/setclonemode <copy|studio>\n"
        "/setmaketarget <ask|join|new>\n"
        "/settitle <新标题> 或 /settitle <短名|链接> | <新标题>\n"
        "/setpack <short_name> | <title>\n"
        "/usepack <short_name> | <title>\n"
        "/packlist 查看最近使用的包\n"
        "/clearpack\n"
        "/center 个人中心(可视化按钮)\n"
        "/menu 打开按钮菜单\n"
        "/invite 获取邀请链接\n"
        "/invitecard 获取邀请海报\n"
        "/quota 查看剩余次数\n"
        "/admin 管理员后台入口\n"
        "/adminstats (管理员) 全局使用统计\n"
        "/adminusers (管理员) 用户列表\n"
        "/adminfind (管理员) 搜索用户\n"
        "/adminexport (管理员) 导出用户CSV\n"
        "/adminhealth (管理员) 运行健康\n"
        "/adminuser (管理员) 用户详情\n"
        "/adminbroadcast (管理员) 群发文本\n"
        "/adminpolicy (管理员) 查看/设置全局策略\n"
        "/adminquota (管理员) 按用户改剩余次数\n"
        "/adminaudit (管理员) 查看后台操作日志\n"
        "/adminlinks (管理员) 设置交流群/作者链接（推荐用后台按钮）\n"
        "/profile 查看当前默认配置\n"
        "/modes 查看所有模式说明\n"
        "/make 😀 | 包标题 | 包短名 | 署名 | mode | fit\n"
        "/me              查看你的用户ID\n"
        "/help            查看简版帮助\n"
        "/helpall         查看完整命令\n\n"
        f"机器人: @{bot_username}"
    )


def serve_modes_text() -> str:
    return (
        "可用视觉模式(mode):\n"
        "- maker: 署名增强(默认)\n"
        "- clean: 纯净不处理\n"
        "- brand: 底部品牌条\n"
        "- circle: 圆形裁切\n"
        "- pixel: 像素风\n"
        "- bw: 黑白风格\n\n"
        "可用适配模式(fit):\n"
        "- contain: 完整保留(默认)\n"
        "- cover: 铺满裁切\n\n"
        "可用克隆策略(clone_mode):\n"
        "- studio: 静态贴纸按模式重渲染(默认)\n"
        "- copy: 静态贴纸尽量原样复制(有 watermark 时会渲染)\n\n"
        "发图默认去向(make_target):\n"
        "- ask: 每次发图弹按钮选择(默认)\n"
        "- join: 默认加入当前包\n"
        "- new: 默认新建包"
    )


def parse_admin_user_ids(raw: str) -> set[int]:
    out: set[int] = set()
    chunks = [x.strip() for x in re.split(r"[,\s]+", raw or "") if x.strip()]
    for item in chunks:
        try:
            out.add(int(item))
        except ValueError:
            continue
    return out


def parse_policy_updates(payload: str) -> dict[str, Any]:
    updates: dict[str, Any] = {}
    if not payload.strip():
        return updates
    tokens = [x.strip() for x in payload.split() if x.strip()]
    for token in tokens:
        if "=" not in token:
            continue
        key, val = token.split("=", 1)
        k = key.strip().lower()
        v = val.strip()
        if k in {
            "free_clone",
            "free_make",
            "invite_reward_clone",
            "invite_reward_make",
            "daily_free_clone",
            "daily_free_make",
        }:
            updates[k] = int(v)
        elif k in {"enforce", "enforce_limits"}:
            updates["enforce_limits"] = v.lower() in {"1", "true", "yes", "on"}
        elif k in {"daily_reset", "daily_reset_enabled"}:
            updates["daily_reset_enabled"] = v.lower() in {"1", "true", "yes", "on"}
    return updates


def parse_admin_quota_payload(payload: str) -> tuple[int, dict[str, int]]:
    raw = payload.strip()
    if not raw:
        raise ValueError("参数为空")
    parts = [x.strip() for x in raw.split() if x.strip()]
    if not parts:
        raise ValueError("参数为空")
    try:
        target_user_id = int(parts[0])
    except ValueError as exc:
        raise ValueError("第一个参数必须是用户ID") from exc

    updates: dict[str, int] = {}
    for token in parts[1:]:
        if "=" not in token:
            continue
        key, val = token.split("=", 1)
        k = key.lower().strip()
        if k not in {"clone", "make"}:
            continue
        updates[k] = max(0, int(val.strip()))
    return target_user_id, updates


def parse_admin_quota_delta_updates(payload: str) -> dict[str, int]:
    updates: dict[str, int] = {}
    text = (payload or "").strip()
    if not text:
        return updates
    # Support spaces around '=', full-width '=' and both CN/EN keys.
    pattern = re.compile(
        r"(克隆|克隆额度|制作|制作额度|clone|make)\s*[=＝]\s*([+-]?\d+)",
        flags=re.IGNORECASE,
    )
    for m in pattern.finditer(text):
        raw_key = (m.group(1) or "").strip().lower()
        val = int((m.group(2) or "0").strip())
        if raw_key in {"克隆", "克隆额度", "clone"}:
            updates["clone"] = val
        elif raw_key in {"制作", "制作额度", "make"}:
            updates["make"] = val
    return updates


def normalize_external_link(value: str) -> str:
    raw = (value or "").strip()
    if not raw:
        return ""
    lowered = raw.lower()
    if lowered in {"-", "none", "null", "clear", "off"}:
        return ""
    if raw.startswith("@"):
        name = raw[1:].strip()
        if not name:
            raise ValueError("用户名不能为空")
        raw = f"https://t.me/{name}"
    elif raw.startswith("t.me/") or raw.startswith("telegram.me/"):
        raw = f"https://{raw}"
    elif re.fullmatch(r"[A-Za-z0-9_]{4,}", raw):
        raw = f"https://t.me/{raw}"

    if not re.match(r"^https?://", raw, flags=re.IGNORECASE):
        raise ValueError("链接必须以 https:// 开头或使用 @username")
    parsed = urlparse(raw)
    if not parsed.netloc:
        raise ValueError("无效链接")
    return raw


def parse_admin_links_updates(payload: str) -> dict[str, str]:
    updates: dict[str, str] = {}
    raw = payload.strip()
    if not raw:
        return updates
    tokens = [x.strip() for x in raw.split() if x.strip()]
    for token in tokens:
        if "=" not in token:
            continue
        key, val = token.split("=", 1)
        k = key.strip().lower()
        v = val.strip()
        if k in {"group", "chat", "community", "group_link"}:
            updates["group"] = normalize_external_link(v)
        elif k in {"author", "contact", "owner", "author_link"}:
            updates["author"] = normalize_external_link(v)
    return updates


def parse_admin_find_query(query: str) -> tuple[str, dict[str, Any]]:
    text = (query or "").strip()
    if not text:
        return "", {}
    filters: dict[str, Any] = {}
    free_parts: list[str] = []
    for token in [x.strip() for x in text.split() if x.strip()]:
        if ":" not in token:
            free_parts.append(token)
            continue
        key, val = token.split(":", 1)
        k = key.strip().lower()
        v = val.strip()
        if not v:
            continue
        if k in {"uid", "user", "user_id"}:
            try:
                filters["uid"] = int(v)
            except ValueError:
                pass
        elif k in {"active", "invited"}:
            filters[k] = v.lower() in {"1", "true", "yes", "on", "y"}
        elif k in {"min_clone_done", "min_make_done", "min_invite"}:
            try:
                filters[k] = max(0, int(v))
            except ValueError:
                pass
        elif k in {"username", "name"}:
            filters[k] = v.lower()
        else:
            free_parts.append(token)
    return " ".join(free_parts).strip().lower(), filters


def filter_users_for_admin(
    items: list[dict[str, Any]],
    *,
    keyword: str = "",
    filters: dict[str, Any] | None = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    f = filters or {}
    out: list[dict[str, Any]] = []
    needle = keyword.strip().lower()
    for item in items:
        uid = int(item.get("user_id", 0))
        username = str(item.get("username", "") or "")
        display_name = str(item.get("display_name", "") or "")
        clone_done = int(item.get("clone_done_total", 0))
        make_done = int(item.get("make_done_total", 0))
        invite_count = int(item.get("invite_count", 0))
        invited_by = int(item.get("invited_by", 0))
        if "uid" in f and uid != int(f["uid"]):
            continue
        if "active" in f:
            is_active = (clone_done + make_done) > 0
            if bool(f["active"]) != is_active:
                continue
        if "invited" in f:
            is_invited = invited_by > 0
            if bool(f["invited"]) != is_invited:
                continue
        if clone_done < int(f.get("min_clone_done", 0)):
            continue
        if make_done < int(f.get("min_make_done", 0)):
            continue
        if invite_count < int(f.get("min_invite", 0)):
            continue
        if f.get("username") and str(f["username"]) not in username.lower():
            continue
        if f.get("name") and str(f["name"]) not in display_name.lower():
            continue
        if needle:
            hay = f"{uid} {username.lower()} {display_name.lower()}"
            if needle not in hay:
                continue
        out.append(item)
        if len(out) >= max(1, min(1000, int(limit))):
            break
    return out


def users_csv_bytes(items: list[dict[str, Any]]) -> bytes:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(
        [
            "user_id",
            "username",
            "display_name",
            "clone_left",
            "make_left",
            "invite_count",
            "invited_by",
            "clone_done_total",
            "make_done_total",
            "created_at",
            "updated_at",
        ]
    )
    for item in items:
        writer.writerow(
            [
                int(item.get("user_id", 0)),
                str(item.get("username", "")),
                str(item.get("display_name", "")),
                int(item.get("clone_left", 0)),
                int(item.get("make_left", 0)),
                int(item.get("invite_count", 0)),
                int(item.get("invited_by", 0)),
                int(item.get("clone_done_total", 0)),
                int(item.get("make_done_total", 0)),
                str(item.get("created_at", "")),
                str(item.get("updated_at", "")),
            ]
        )
    return buf.getvalue().encode("utf-8-sig")


def policy_text(policy: dict[str, Any]) -> str:
    return (
        "后台配额策略:\n"
        f"- 新用户克隆次数: {int(policy.get('free_clone', 0))}\n"
        f"- 新用户制作次数: {int(policy.get('free_make', 0))}\n"
        f"- 邀请奖励克隆: {int(policy.get('invite_reward_clone', 0))}\n"
        f"- 邀请奖励制作: {int(policy.get('invite_reward_make', 0))}\n"
        f"- 是否启用限制: {'是' if bool(policy.get('enforce_limits', True)) else '否'}\n"
        f"- 每日重置开关: {'开' if bool(policy.get('daily_reset_enabled', True)) else '关'}\n"
        f"- 每日保底克隆: {int(policy.get('daily_free_clone', 0))}\n"
        f"- 每日保底制作: {int(policy.get('daily_free_make', 0))}"
    )


def external_links_text(links: dict[str, str]) -> str:
    group_link = str(links.get("group", "")).strip() or "(未设置)"
    author_link = str(links.get("author", "")).strip() or "(未设置)"
    return (
        "外链设置:\n"
        f"- 交流群链接: {group_link}\n"
        f"- 作者联系方式: {author_link}\n\n"
        "请使用下方按钮进行设置或清空。"
    )


def admin_help_text() -> str:
    return (
        "管理员后台\n"
        "建议直接使用下方按钮操作：\n"
        "1) 全局统计\n"
        "2) 用户列表 / 搜索用户 / 导出\n"
        "3) 策略查看\n"
        "4) 外链设置（交流群/作者）\n"
        "5) 用户详情里可直接增减额度\n"
        "6) 操作日志（审计）\n"
        "7) 运行健康"
    )


def admin_stats_text(stats: dict[str, Any]) -> str:
    policy = stats.get("policy", DEFAULT_USAGE_POLICY)
    return (
        "后台总览:\n"
        f"- 总用户数: {int(stats.get('total_users', 0))}\n"
        f"- 已被邀请用户: {int(stats.get('invited_users', 0))}\n"
        f"- 总邀请次数: {int(stats.get('total_invites', 0))}\n"
        f"- 累计克隆完成: {int(stats.get('total_clone_done', 0))}\n"
        f"- 累计制作完成: {int(stats.get('total_make_done', 0))}\n"
        f"- 全站剩余克隆额度: {int(stats.get('total_clone_left', 0))}\n"
        f"- 全站剩余制作额度: {int(stats.get('total_make_left', 0))}\n"
        f"- 已发邀请奖励: 克隆={int(stats.get('total_reward_clone', 0))}，制作={int(stats.get('total_reward_make', 0))}\n"
        f"- 是否启用限制: {'是' if bool(policy.get('enforce_limits', True)) else '否'}\n"
        f"- 每日重置: {'开' if bool(policy.get('daily_reset_enabled', True)) else '关'}"
    )


def admin_audit_text(items: list[dict[str, Any]]) -> str:
    lines = ["后台操作日志（最近）"]
    if not items:
        lines.append("(暂无)")
        return "\n".join(lines)
    for item in items[:30]:
        at = str(item.get("at") or "").replace("T", " ")
        if "+" in at:
            at = at.split("+", 1)[0]
        if "." in at:
            at = at.split(".", 1)[0]
        actor = int(item.get("actor_user_id", 0))
        action = str(item.get("action", "") or "-")
        detail = str(item.get("detail", "") or "-")
        target = int(item.get("target_user_id", 0))
        if target > 0:
            lines.append(f"- {at} | 管理员:{actor} | {action} | 用户:{target} | {detail}")
        else:
            lines.append(f"- {at} | 管理员:{actor} | {action} | {detail}")
    return "\n".join(lines)


def admin_users_page_text(page_data: dict[str, Any]) -> str:
    lines = [
        f"用户列表 第 {int(page_data.get('page', 1))}/{int(page_data.get('pages', 1))} 页 "
        f"(共 {int(page_data.get('total', 0))} 人)"
    ]
    items = page_data.get("items", [])
    if not items:
        lines.append("(空)")
        return "\n".join(lines)
    for item in items:
        uid = int(item.get("user_id", 0))
        name = item.get("display_name") or item.get("username") or "-"
        lines.append(
            f"- {uid} {name} | 剩余: 克隆{int(item.get('clone_left', 0))}/制作{int(item.get('make_left', 0))} "
            f"| 完成: 克隆{int(item.get('clone_done_total', 0))}/制作{int(item.get('make_done_total', 0))} | 邀请{int(item.get('invite_count', 0))}"
        )
    return "\n".join(lines)


def admin_search_results_text(query: str, items: list[dict[str, Any]]) -> str:
    lines = [f"搜索结果: {query}"]
    if not items:
        lines.append("(无匹配用户)")
        return "\n".join(lines)
    for item in items:
        uid = int(item.get("user_id", 0))
        name = item.get("display_name") or item.get("username") or "-"
        lines.append(
            f"- {uid} {name} | 克隆剩余={int(item.get('clone_left', 0))} 制作剩余={int(item.get('make_left', 0))}"
        )
    return "\n".join(lines)


def admin_user_detail_text(
    user_id: int,
    usage_detail: dict[str, Any],
    settings: dict[str, Any],
    packs: list[dict[str, Any]],
) -> str:
    lines = [
        f"用户ID: {user_id}",
        f"用户名: {usage_detail.get('username', '')}",
        f"显示名: {usage_detail.get('display_name', '')}",
        f"邀请人ID: {int(usage_detail.get('invited_by', 0))}",
        f"已邀请人数: {int(usage_detail.get('invite_count', 0))}",
        f"克隆剩余额度: {int(usage_detail.get('clone_left', 0))}",
        f"制作剩余额度: {int(usage_detail.get('make_left', 0))}",
        f"累计克隆完成: {int(usage_detail.get('clone_done_total', 0))}",
        f"累计制作完成: {int(usage_detail.get('make_done_total', 0))}",
        f"已发邀请奖励: 克隆={int(usage_detail.get('invite_reward_clone_total', 0))}，制作={int(usage_detail.get('invite_reward_make_total', 0))}",
        f"当前包: {(settings.get('current_pack_short') or '').strip() or '-'}",
        (
            f"当前模式: 视觉={visual_mode_label(settings.get('mode'))} "
            f"适配={fit_mode_label(settings.get('fit_mode'))} "
            f"克隆策略={clone_mode_label(settings.get('clone_mode'))}"
        ),
    ]
    if packs:
        lines.append("最近包:")
        for item in packs[:5]:
            lines.append(
                f"- {(item.get('title') or item.get('short_name'))} ({item.get('short_name')}) x{int(item.get('count', 0))}"
            )
    return "\n".join(lines)


def generate_invite_card(
    *,
    invite_link: str,
    user_id: int,
    reward_clone: int,
    reward_make: int,
) -> bytes:
    width, height = 1080, 1440
    card = Image.new("RGB", (width, height), (245, 248, 255))
    draw = ImageDraw.Draw(card, "RGBA")

    # header strip
    draw.rectangle((0, 0, width, 220), fill=(34, 104, 255, 255))
    draw.rectangle((48, 250, width - 48, height - 48), fill=(255, 255, 255, 255), outline=(228, 234, 245, 255), width=2)

    title_font = _load_font(52)
    text_font = _load_font(30)
    small_font = _load_font(24)

    draw.text((64, 72), "邀请好友，解锁更多次数", font=title_font, fill=(255, 255, 255, 255))
    draw.text((72, 290), f"你的ID: {user_id}", font=small_font, fill=(90, 97, 110, 255))
    draw.text((72, 340), f"邀请1人奖励: clone +{reward_clone} / make +{reward_make}", font=text_font, fill=(38, 45, 56, 255))

    qr = qrcode.QRCode(
        version=4,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=8,
        border=2,
    )
    qr.add_data(invite_link)
    qr.make(fit=True)
    qr_img = qr.make_image(fill_color="black", back_color="white").convert("RGB")
    qr_img = qr_img.resize((520, 520), Image.Resampling.NEAREST)
    card.paste(qr_img, (280, 430))

    draw.text((205, 990), "扫码或长按识别二维码", font=text_font, fill=(38, 45, 56, 255))
    draw.text((92, 1060), invite_link, font=small_font, fill=(34, 104, 255, 255))
    draw.text((92, 1120), "进入机器人后自动绑定邀请关系", font=small_font, fill=(112, 120, 135, 255))
    draw.text((92, 1168), "绑定后可立即获得更多克隆/制作次数", font=small_font, fill=(112, 120, 135, 255))

    out = io.BytesIO()
    card.save(out, format="PNG", optimize=True)
    return out.getvalue()


def user_profile_text(user_id: int, settings: dict[str, Any], usage: dict[str, Any]) -> str:
    wm = settings.get("watermark") or "(空)"
    mode = visual_mode_label(settings.get("mode"))
    fit_mode = fit_mode_label(settings.get("fit_mode"))
    clone_mode = clone_mode_label(settings.get("clone_mode"))
    make_target = make_target_mode_label(settings.get("make_target_mode"))
    short_name = (settings.get("current_pack_short") or "").strip() or "(自动)"
    title = (settings.get("current_pack_title") or "").strip() or "(自动)"
    policy = usage.get("policy", DEFAULT_USAGE_POLICY)
    daily_enabled = bool(policy.get("daily_reset_enabled", True))
    return (
        f"用户ID：{user_id}\n"
        f"制作人署名：{wm}\n"
        f"视觉模式：{mode}（适配：{fit_mode}，克隆策略：{clone_mode}）\n"
        f"发图默认去向：{make_target}\n"
        f"剩余次数：克隆 {int(usage.get('clone_left', 0))} 次，制作 {int(usage.get('make_left', 0))} 次\n"
        f"已邀请好友：{int(usage.get('invite_count', 0))} 人\n"
        f"每日保底：{'开启' if daily_enabled else '关闭'}（克隆≥{int(policy.get('daily_free_clone', 0))}，制作≥{int(policy.get('daily_free_make', 0))}）\n"
        f"当前包短名：{short_name}\n"
        f"当前包标题：{title}"
    )


def user_center_text(
    user_id: int,
    settings: dict[str, Any],
    packs: list[dict[str, Any]],
    usage: dict[str, Any],
    invite_link: str,
    external_links: dict[str, str],
) -> str:
    current_short = (settings.get("current_pack_short") or "").strip()
    policy = usage.get("policy", DEFAULT_USAGE_POLICY)
    wm = settings.get("watermark") or "(空)"
    mode = visual_mode_label(settings.get("mode"))
    fit_mode = fit_mode_label(settings.get("fit_mode"))
    clone_mode = clone_mode_label(settings.get("clone_mode"))
    make_target = make_target_mode_label(settings.get("make_target_mode"))
    display_name = usage.get("display_name") or usage.get("username") or str(user_id)
    parts = [
        "🎛 个人中心",
        f"👤 用户: {display_name} ({user_id})",
        f"🧩 剩余次数: 克隆 {int(usage.get('clone_left', 0))} | 制作 {int(usage.get('make_left', 0))}",
        f"🤝 邀请人数: {int(usage.get('invite_count', 0))} 人",
        f"🏷 制作人署名: {wm}",
        f"⚙ 当前模式: {mode} / {fit_mode} / {clone_mode}",
        f"🖼 发图默认: {make_target}",
        (
            f"🎁 邀请奖励: 每邀请1人 +克隆 {int(policy.get('invite_reward_clone', 0))} "
            f"+制作 {int(policy.get('invite_reward_make', 0))}"
        ),
    ]
    if current_short:
        parts.append(f"📦 当前包: https://t.me/addstickers/{current_short}")
    else:
        parts.append("📦 当前包: (自动)")

    if not packs:
        parts.append("🕘 最近包: 暂无")
    else:
        lines = ["🕘 最近包:"]
        for idx, item in enumerate(packs[:3], start=1):
            title = item.get("title") or item.get("short_name")
            short_name = item.get("short_name")
            count = int(item.get("count", 0))
            lines.append(f"{idx}. {title}（{short_name}）+{count}")
        parts.append("\n".join(lines))

    parts.append(f"🔗 邀请链接: {invite_link}")
    group_link = str(external_links.get("group", "")).strip()
    author_link = str(external_links.get("author", "")).strip()
    if group_link:
        parts.append(f"👥 交流群: {group_link}")
    if author_link:
        parts.append(f"🧑‍💻 联系作者: {author_link}")
    parts.append("💡 提示: 直接发图片可继续添加到当前包")
    return "\n".join(parts)


def quota_panel_text(usage: dict[str, Any], invite_link: str) -> str:
    policy = usage.get("policy", DEFAULT_USAGE_POLICY)
    return (
        "📊 使用额度\n"
        f"克隆剩余: {int(usage.get('clone_left', 0))}\n"
        f"制作剩余: {int(usage.get('make_left', 0))}\n"
        f"累计克隆: {int(usage.get('clone_done_total', 0))}\n"
        f"累计制作: {int(usage.get('make_done_total', 0))}\n"
        f"已邀请好友: {int(usage.get('invite_count', 0))}\n"
        f"每日保底: 克隆≥{int(policy.get('daily_free_clone', 0))}, 制作≥{int(policy.get('daily_free_make', 0))}\n"
        f"每日重置: {'开启' if bool(policy.get('daily_reset_enabled', True)) else '关闭'}\n"
        f"邀请奖励: 克隆+{int(policy.get('invite_reward_clone', 0))}, 制作+{int(policy.get('invite_reward_make', 0))}\n"
        f"邀请链接: {invite_link}"
    )


def recent_panel_text(usage: dict[str, Any]) -> str:
    lines = ["🕘 最近记录"]

    clone_rows = usage.get("recent_clone", [])
    lines.append("克隆:")
    if clone_rows:
        for idx, item in enumerate(clone_rows[:5], start=1):
            lines.append(f"{idx}. {item.get('brief', '-')}")
    else:
        lines.append("- 暂无")

    make_rows = usage.get("recent_make", [])
    lines.append("")
    lines.append("制作:")
    if make_rows:
        for idx, item in enumerate(make_rows[:5], start=1):
            lines.append(f"{idx}. {item.get('brief', '-')}")
    else:
        lines.append("- 暂无")

    invite_rows = usage.get("recent_invite", [])
    lines.append("")
    lines.append("邀请:")
    if invite_rows:
        for idx, item in enumerate(invite_rows[:5], start=1):
            name = item.get("display_name") or item.get("username") or item.get("uid")
            lines.append(
                f"{idx}. {name} (clone+{int(item.get('reward_clone', 0))}, make+{int(item.get('reward_make', 0))})"
            )
    else:
        lines.append("- 暂无")
    return "\n".join(lines)


def settings_panel_text(settings: dict[str, Any]) -> str:
    wm = settings.get("watermark") or "(空)"
    mode = visual_mode_label(settings.get("mode"))
    fit_mode = fit_mode_label(settings.get("fit_mode"))
    clone_mode = clone_mode_label(settings.get("clone_mode"))
    make_target = make_target_mode_label(settings.get("make_target_mode"))
    short_name = (settings.get("current_pack_short") or "").strip() or "(自动)"
    title = (settings.get("current_pack_title") or "").strip() or "(自动)"
    return (
        "⚙ 参数设置\n"
        f"制作人署名: {wm}\n"
        f"视觉模式: {mode}\n"
        f"适配模式: {fit_mode}\n"
        f"克隆策略: {clone_mode}\n"
        f"发图去向: {make_target}\n"
        f"当前包短名: {short_name}\n"
        f"当前包标题: {title}\n\n"
        "可通过下方按钮快速切换。"
    )


def packs_panel_text(packs: list[dict[str, Any]], current_pack_short: str) -> str:
    if not packs:
        return "📦 最近表情包\n暂无记录，先发一张图片开始制作。"
    lines = ["📦 最近表情包 (点击按钮可切换当前包)"]
    for idx, item in enumerate(packs[:8], start=1):
        short = str(item.get("short_name") or "").strip()
        title = str(item.get("title") or short).strip() or short
        count = int(item.get("count", 0))
        mark = " <- 当前" if short and short == current_pack_short else ""
        lines.append(f"{idx}. {title} ({short}) +{count}{mark}")
    return "\n".join(lines)


async def safe_edit_status(
    client: TelegramBotClient,
    chat_id: int,
    message_id: int,
    text: str,
) -> None:
    try:
        await client.edit_message_text(chat_id, message_id, text)
    except TelegramAPIError:
        await client.send_message(chat_id, text)


async def handle_clone_request(
    client: TelegramBotClient,
    *,
    chat_id: int,
    user_id: int,
    request_text: str,
    bot_username: str,
    user_prefs: UserPrefsStore,
    progress_step: int,
) -> dict[str, Any]:
    req = parse_clone_payload(request_text)
    source = (req.get("source") or "").strip()
    if not source:
        raise ValueError("缺少来源。")

    settings = user_prefs.get_user_settings(user_id)
    wm = (req.get("watermark") or "").strip() or (settings.get("watermark") or "").strip()
    new_title = req.get("new_title")
    new_short_name = req.get("new_short_name")
    visual_mode = normalize_visual_mode(req.get("mode") or settings.get("mode"))
    fit_mode = normalize_fit_mode(req.get("fit_mode") or settings.get("fit_mode"))
    clone_mode = normalize_clone_mode(req.get("clone_mode") or settings.get("clone_mode"))

    status = await client.send_message(chat_id, "任务已接收，开始克隆...")
    status_id = int(status["message_id"])
    progress_state = {"last": -1}

    async def on_info(message: str) -> None:
        await client.send_message(chat_id, f"提示: {message}")

    async def on_progress(done: int, total: int) -> None:
        if total <= 0:
            return
        should_update = done in {0, 1, total} or done - progress_state["last"] >= progress_step
        if not should_update:
            return
        progress_state["last"] = done
        await safe_edit_status(client, chat_id, status_id, f"克隆进度: {done}/{total}")

    result = await clone_sticker_set(
        client,
        source_input=source,
        owner_user_id=user_id,
        bot_username=bot_username,
        new_short_name=(new_short_name or None),
        new_title=(new_title or None),
        watermark=(wm or None),
        watermark_pos="br",
        watermark_opacity=145,
        visual_mode=visual_mode,
        fit_mode=fit_mode,
        clone_mode=clone_mode,
        progress_cb=on_progress,
        info_cb=on_info,
    )

    await safe_edit_status(
        client,
        chat_id,
        status_id,
        (
            f"完成: https://t.me/addstickers/{result['target_short_name']}\n"
            f"模式: 克隆策略={clone_mode_label(result['clone_mode'])} "
            f"视觉={visual_mode_label(result['visual_mode'])} "
            f"适配={fit_mode_label(result['fit_mode'])}"
        ),
    )
    return result


async def handle_make_request(
    client: TelegramBotClient,
    *,
    chat_id: int,
    user_id: int,
    image_bytes: bytes,
    request_text: str,
    bot_username: str,
    user_prefs: UserPrefsStore,
    force_new_pack: bool = False,
) -> dict[str, Any]:
    req = parse_make_payload(request_text)
    settings = user_prefs.get_user_settings(user_id)
    wm = (req.get("watermark") or "").strip() or (settings.get("watermark") or "").strip()
    visual_mode = normalize_visual_mode(req.get("mode") or settings.get("mode"))
    fit_mode = normalize_fit_mode(req.get("fit_mode") or settings.get("fit_mode"))
    default_short = (settings.get("current_pack_short") or "").strip() or None
    default_title = (settings.get("current_pack_title") or "").strip() or None
    selected_short = req.get("short_name")
    target_short = (selected_short or None) if force_new_pack else (selected_short or default_short)

    status = await client.send_message(chat_id, "收到图片，开始制作贴纸...")
    status_id = int(status["message_id"])

    result = await create_or_add_single_sticker(
        client,
        owner_user_id=user_id,
        bot_username=bot_username,
        image_bytes=image_bytes,
        emoji_text=req.get("emoji"),
        pack_short_name=target_short,
        pack_title=req.get("title") or default_title,
        watermark=(wm or None),
        watermark_pos="br",
        watermark_opacity=145,
        visual_mode=visual_mode,
        fit_mode=fit_mode,
        force_new_pack=force_new_pack,
    )
    user_prefs.touch_pack(
        user_id=user_id,
        short_name=result["target_short_name"],
        title=result.get("target_title"),
        count_add=1,
    )

    if result["action"] == "created":
        action_text = "已创建并加入"
    elif result["action"] == "created_overflow":
        action_text = "原包已满，已自动创建新包并加入"
    else:
        action_text = "已加入"
    await safe_edit_status(
        client,
        chat_id,
        status_id,
        (
            f"{action_text}: https://t.me/addstickers/{result['target_short_name']}\n"
            f"模式: 视觉={visual_mode_label(result['visual_mode'])} 适配={fit_mode_label(result['fit_mode'])}\n"
            "后续继续添加: 直接再发图片即可。"
        ),
    )
    return result


async def cmd_serve(client: TelegramBotClient, args: argparse.Namespace) -> None:
    me = await client.call("getMe")
    bot_username = me["username"]
    console.print(f"服务已启动: @{bot_username}", style="green")

    locks: dict[int, asyncio.Lock] = {}
    sem = asyncio.Semaphore(args.max_jobs)
    prefs = UserPrefsStore()
    usage = UsageStore()
    audit = AdminAuditStore()
    admin_user_ids = parse_admin_user_ids(os.getenv("ADMIN_USER_IDS", ""))
    serve_mode = (getattr(args, "serve_mode", None) or os.getenv("BOT_SERVE_MODE", "poll")).strip().lower()
    if serve_mode not in {"poll", "webhook"}:
        serve_mode = "poll"
    webhook_url = (getattr(args, "webhook_url", None) or os.getenv("BOT_WEBHOOK_URL", "")).strip()
    webhook_path = (getattr(args, "webhook_path", None) or os.getenv("BOT_WEBHOOK_PATH", "/telegram/webhook")).strip() or "/telegram/webhook"
    if not webhook_path.startswith("/"):
        webhook_path = f"/{webhook_path}"
    webhook_host = (getattr(args, "webhook_host", None) or os.getenv("BOT_WEBHOOK_HOST", "0.0.0.0")).strip() or "0.0.0.0"
    webhook_port = int(getattr(args, "webhook_port", None) or int(os.getenv("BOT_WEBHOOK_PORT", "8080") or "8080"))
    webhook_secret = (getattr(args, "webhook_secret", None) or os.getenv("BOT_WEBHOOK_SECRET", "")).strip()
    console.print(f"服务模式: {serve_mode}", style="cyan")
    offset = 0
    active_tasks: set[asyncio.Task[Any]] = set()
    admin_input_state: dict[int, dict[str, Any]] = {}
    user_input_state: dict[int, dict[str, Any]] = {}
    pending_make_choice: dict[int, dict[str, Any]] = {}
    broadcast_lock = asyncio.Lock()
    rate_window_seconds = max(3, int(os.getenv("BOT_RATE_WINDOW_SECONDS", "10") or "10"))
    rate_max_hits = max(3, int(os.getenv("BOT_RATE_MAX_HITS", "10") or "10"))
    user_req_log: dict[int, list[int]] = {}
    runtime_stats: dict[str, int] = {
        "updates_total": 0,
        "messages_total": 0,
        "callbacks_total": 0,
        "clone_ok": 0,
        "clone_fail": 0,
        "make_ok": 0,
        "make_fail": 0,
        "rate_limited": 0,
    }
    network_hint_shown = False
    conflict_hint_shown = False

    def is_admin(user_id: int) -> bool:
        return user_id in admin_user_ids

    def admin_log(
        actor_user_id: int,
        action: str,
        detail: str,
        *,
        target_user_id: int | None = None,
        extra: dict[str, Any] | None = None,
    ) -> None:
        try:
            audit.log(
                actor_user_id=actor_user_id,
                action=action,
                detail=detail,
                target_user_id=target_user_id,
                extra=extra,
            )
        except Exception:
            pass

    def _now_ts() -> int:
        return int(time.time())

    def check_rate_limit(user_id: int) -> bool:
        if is_admin(user_id):
            return False
        now = _now_ts()
        arr = user_req_log.get(user_id, [])
        arr = [ts for ts in arr if now - ts <= rate_window_seconds]
        arr.append(now)
        user_req_log[user_id] = arr
        if len(arr) > rate_max_hits:
            runtime_stats["rate_limited"] = int(runtime_stats.get("rate_limited", 0)) + 1
            return True
        return False

    def runtime_health_text() -> str:
        return (
            "运行健康:\n"
            f"- 更新总数: {int(runtime_stats.get('updates_total', 0))}\n"
            f"- 消息总数: {int(runtime_stats.get('messages_total', 0))}\n"
            f"- 回调总数: {int(runtime_stats.get('callbacks_total', 0))}\n"
            f"- 克隆成功/失败: {int(runtime_stats.get('clone_ok', 0))}/{int(runtime_stats.get('clone_fail', 0))}\n"
            f"- 制作成功/失败: {int(runtime_stats.get('make_ok', 0))}/{int(runtime_stats.get('make_fail', 0))}\n"
            f"- 触发限流: {int(runtime_stats.get('rate_limited', 0))}\n"
            f"- 活跃任务数: {len(active_tasks)}"
        )

    def set_admin_input_state(user_id: int, chat_id: int, mode: str, **extra: Any) -> None:
        state: dict[str, Any] = {
            "mode": mode,
            "chat_id": int(chat_id),
            "created_at": _now_ts(),
        }
        state.update(extra)
        admin_input_state[user_id] = state

    def get_admin_input_state(user_id: int, chat_id: int) -> dict[str, Any] | None:
        state = admin_input_state.get(user_id)
        if not isinstance(state, dict):
            return None
        if int(state.get("chat_id", 0)) not in {0, int(chat_id)}:
            return None
        created_at = int(state.get("created_at", 0))
        if created_at <= 0 or (_now_ts() - created_at) > ADMIN_INPUT_TTL_SECONDS:
            admin_input_state.pop(user_id, None)
            return None
        return state

    def keep_admin_input_state_alive(user_id: int) -> None:
        state = admin_input_state.get(user_id)
        if isinstance(state, dict):
            state["created_at"] = _now_ts()
            admin_input_state[user_id] = state

    def set_user_input_state(user_id: int, chat_id: int, mode: str, **extra: Any) -> None:
        state: dict[str, Any] = {
            "mode": mode,
            "chat_id": int(chat_id),
            "created_at": _now_ts(),
        }
        state.update(extra)
        user_input_state[user_id] = state

    def get_user_input_state(user_id: int, chat_id: int) -> dict[str, Any] | None:
        state = user_input_state.get(user_id)
        if not isinstance(state, dict):
            return None
        if int(state.get("chat_id", 0)) not in {0, int(chat_id)}:
            return None
        created_at = int(state.get("created_at", 0))
        if created_at <= 0 or (_now_ts() - created_at) > ADMIN_INPUT_TTL_SECONDS:
            user_input_state.pop(user_id, None)
            return None
        return state

    def keep_user_input_state_alive(user_id: int) -> None:
        state = user_input_state.get(user_id)
        if isinstance(state, dict):
            state["created_at"] = _now_ts()
            user_input_state[user_id] = state

    def set_pending_make_choice(
        user_id: int,
        chat_id: int,
        image_bytes: bytes,
        make_payload: str,
    ) -> None:
        pending_make_choice[user_id] = {
            "chat_id": int(chat_id),
            "created_at": _now_ts(),
            "image_bytes": image_bytes,
            "make_payload": make_payload,
        }

    def get_pending_make_choice(user_id: int, chat_id: int) -> dict[str, Any] | None:
        state = pending_make_choice.get(user_id)
        if not isinstance(state, dict):
            return None
        if int(state.get("chat_id", 0)) not in {0, int(chat_id)}:
            return None
        created_at = int(state.get("created_at", 0))
        if created_at <= 0 or (_now_ts() - created_at) > ADMIN_INPUT_TTL_SECONDS:
            pending_make_choice.pop(user_id, None)
            return None
        return state

    def _btn(text: str, cb: str | None = None, url: str | None = None) -> dict[str, str]:
        payload: dict[str, str] = {"text": text}
        if cb:
            payload["callback_data"] = cb
        if url:
            payload["url"] = url
        return payload

    def center_keyboard(user_id: int, settings: dict[str, Any], external_links: dict[str, str]) -> dict[str, Any]:
        rows: list[list[dict[str, str]]] = [
            [_btn("🔄 刷新", "ctr:refresh"), _btn("📊 使用额度", "ctr:quota")],
            [_btn("📦 最近表情包", "ctr:packs"), _btn("🕘 最近记录", "ctr:recent")],
            [_btn("⚙ 参数设置", "ctr:settings"), _btn("🎁 邀请海报", "ctr:invitecard")],
            [_btn("❓ 帮助", "ctr:help")],
        ]
        link_row: list[dict[str, str]] = []
        group_link = str(external_links.get("group", "")).strip()
        author_link = str(external_links.get("author", "")).strip()
        if group_link:
            link_row.append(_btn("👥 加入交流群", url=group_link))
        if author_link:
            link_row.append(_btn("🧑‍💻 联系作者", url=author_link))
        if link_row:
            rows.append(link_row)
        current_short = (settings.get("current_pack_short") or "").strip()
        if current_short:
            rows.append([_btn("🌐 打开当前包", url=f"https://t.me/addstickers/{current_short}")])
        if is_admin(user_id):
            rows.append([_btn("🛠 管理后台", "adm:home")])
        return {"inline_keyboard": rows}

    def settings_keyboard() -> dict[str, Any]:
        return {
            "inline_keyboard": [
                [_btn("🎨 视觉模式", "set:mode"), _btn("🧭 适配模式", "set:fit")],
                [_btn("🧪 克隆策略", "set:clone"), _btn("🖼 发图去向", "set:maketarget")],
                [_btn("🧹 清空署名", "set:wmclear"), _btn("✏ 修改包标题", "set:title")],
                [_btn("📦 清空当前包", "set:packclear")],
                [_btn("🔙 返回中心", "ctr:refresh")],
            ]
        }

    def make_target_keyboard(current_target: str) -> dict[str, Any]:
        return {
            "inline_keyboard": [
                [
                    _btn(_pick_label(f"{MAKE_TARGET_MODE_LABELS['ask']}(ask)", current_target == "ask"), "set:maketargetv:ask"),
                    _btn(_pick_label(f"{MAKE_TARGET_MODE_LABELS['join']}(join)", current_target == "join"), "set:maketargetv:join"),
                ],
                [
                    _btn(_pick_label(f"{MAKE_TARGET_MODE_LABELS['new']}(new)", current_target == "new"), "set:maketargetv:new"),
                ],
                [_btn("🔙 返回设置", "ctr:settings"), _btn("🏠 返回中心", "ctr:refresh")],
            ]
        }

    def make_choice_keyboard(current_short: str) -> dict[str, Any]:
        rows: list[list[dict[str, str]]] = [
            [_btn("📦 加入当前包", "mkc:join"), _btn("🆕 新建表情包", "mkc:new")],
            [_btn("❌ 取消本次", "mkc:cancel")],
        ]
        if current_short:
            rows.append([_btn("🌐 打开当前包", url=f"https://t.me/addstickers/{current_short}")])
        return {"inline_keyboard": rows}

    def _pick_label(label: str, is_active: bool) -> str:
        return f"✅ {label}" if is_active else label

    def mode_keyboard(current_mode: str) -> dict[str, Any]:
        modes = ["maker", "clean", "brand", "circle", "pixel", "bw"]
        rows: list[list[dict[str, str]]] = []
        for i in range(0, len(modes), 2):
            row: list[dict[str, str]] = []
            for mode in modes[i : i + 2]:
                label = f"{VISUAL_MODE_LABELS.get(mode, mode)}({mode})"
                row.append(_btn(_pick_label(label, mode == current_mode), f"set:modev:{mode}"))
            rows.append(row)
        rows.append([_btn("🔙 返回设置", "ctr:settings"), _btn("🏠 返回中心", "ctr:refresh")])
        return {"inline_keyboard": rows}

    def fit_keyboard(current_fit: str) -> dict[str, Any]:
        return {
            "inline_keyboard": [
                [
                    _btn(_pick_label(f"{FIT_MODE_LABELS['contain']}(contain)", current_fit == "contain"), "set:fitv:contain"),
                    _btn(_pick_label(f"{FIT_MODE_LABELS['cover']}(cover)", current_fit == "cover"), "set:fitv:cover"),
                ],
                [_btn("🔙 返回设置", "ctr:settings"), _btn("🏠 返回中心", "ctr:refresh")],
            ]
        }

    def clone_mode_keyboard(current_clone: str) -> dict[str, Any]:
        return {
            "inline_keyboard": [
                [
                    _btn(
                        _pick_label(f"{CLONE_MODE_LABELS['studio']}(studio)", current_clone == "studio"),
                        "set:clonev:studio",
                    ),
                    _btn(
                        _pick_label(f"{CLONE_MODE_LABELS['copy']}(copy)", current_clone == "copy"),
                        "set:clonev:copy",
                    ),
                ],
                [_btn("🔙 返回设置", "ctr:settings"), _btn("🏠 返回中心", "ctr:refresh")],
            ]
        }

    def packs_keyboard(
        packs: list[dict[str, Any]],
        current_pack_short: str,
    ) -> dict[str, Any]:
        rows: list[list[dict[str, str]]] = []
        for idx, item in enumerate(packs[:8]):
            short_name = str(item.get("short_name") or "").strip()
            if not short_name:
                continue
            title = str(item.get("title") or short_name).strip() or short_name
            mark = "✅ " if short_name == current_pack_short else ""
            text = f"{mark}{title[:18]}"
            rows.append([_btn(text, f"pack:use:{idx}"), _btn("🌐 打开", url=f"https://t.me/addstickers/{short_name}")])
        rows.append([_btn("🔙 返回中心", "ctr:refresh")])
        return {"inline_keyboard": rows}

    def help_keyboard() -> dict[str, Any]:
        return {
            "inline_keyboard": [
                [_btn("📚 全部命令", "ctr:helpall")],
                [_btn("🔙 返回中心", "ctr:refresh")],
            ]
        }

    def admin_home_keyboard() -> dict[str, Any]:
        return {
            "inline_keyboard": [
                [_btn("📈 全局统计", "adm:stats"), _btn("👥 用户列表", "adm:users:1")],
                [_btn("🔎 搜索用户", "adm:search"), _btn("🩺 运行健康", "adm:health")],
                [_btn("📤 导出CSV", "adm:export:all")],
                [_btn("📜 策略", "adm:policy"), _btn("🔗 外链设置", "adm:links")],
                [_btn("🧾 操作日志", "adm:audit")],
                [_btn("🔄 刷新", "adm:home")],
                [_btn("🏠 返回中心", "ctr:refresh")],
            ]
        }

    def admin_links_keyboard() -> dict[str, Any]:
        return {
            "inline_keyboard": [
                [_btn("👥 设置交流群", "adm:link:set:group"), _btn("🧑‍💻 设置作者联系方式", "adm:link:set:author")],
                [_btn("🧹 清空交流群", "adm:link:clear:group"), _btn("🧹 清空作者联系方式", "adm:link:clear:author")],
                [_btn("🔄 刷新", "adm:links"), _btn("🔙 后台首页", "adm:home")],
                [_btn("🏠 返回中心", "ctr:refresh")],
            ]
        }

    def admin_users_keyboard(page_data: dict[str, Any]) -> dict[str, Any]:
        page = int(page_data.get("page", 1))
        pages = int(page_data.get("pages", 1))
        items = page_data.get("items", [])
        rows: list[list[dict[str, str]]] = []
        for item in items[:8]:
            uid = int(item.get("user_id", 0))
            if uid <= 0:
                continue
            name = str(item.get("display_name") or item.get("username") or uid)
            rows.append([_btn(f"👤 {name[:18]} ({uid})", f"adm:user:{uid}")])
        nav_row: list[dict[str, str]] = []
        if page > 1:
            nav_row.append(_btn("⬅ 上一页", f"adm:users:{page - 1}"))
        if page < pages:
            nav_row.append(_btn("下一页 ➡", f"adm:users:{page + 1}"))
        if nav_row:
            rows.append(nav_row)
        rows.append([_btn("🔎 搜索用户", "adm:search")])
        rows.append([_btn("🔙 后台首页", "adm:home"), _btn("🏠 返回中心", "ctr:refresh")])
        return {"inline_keyboard": rows}

    def admin_search_keyboard(items: list[dict[str, Any]]) -> dict[str, Any]:
        rows: list[list[dict[str, str]]] = []
        for item in items[:10]:
            uid = int(item.get("user_id", 0))
            if uid <= 0:
                continue
            name = str(item.get("display_name") or item.get("username") or uid)
            rows.append([_btn(f"👤 {name[:18]} ({uid})", f"adm:user:{uid}")])
        rows.append([_btn("🔎 继续搜索", "adm:search")])
        rows.append([_btn("🔙 后台首页", "adm:home"), _btn("🏠 返回中心", "ctr:refresh")])
        return {"inline_keyboard": rows}

    def admin_detail_keyboard(target_user_id: int) -> dict[str, Any]:
        return {
            "inline_keyboard": [
                [_btn("➕克隆+1", f"adm:q:{target_user_id}:clone:1"), _btn("➕克隆+5", f"adm:q:{target_user_id}:clone:5")],
                [_btn("➕制作+1", f"adm:q:{target_user_id}:make:1"), _btn("➕制作+5", f"adm:q:{target_user_id}:make:5")],
                [_btn("➖克隆-1", f"adm:q:{target_user_id}:clone:-1"), _btn("➖制作-1", f"adm:q:{target_user_id}:make:-1")],
                [_btn("✍ 自定义增减", f"adm:qinput:{target_user_id}")],
                [_btn("🔄 刷新详情", f"adm:user:{target_user_id}")],
                [_btn("👥 返回用户列表", "adm:users:1"), _btn("🔙 后台首页", "adm:home")],
                [_btn("🏠 返回中心", "ctr:refresh")],
            ]
        }

    async def edit_or_send(
        *,
        chat_id: int,
        text: str,
        reply_markup: dict[str, Any] | None = None,
        message_id: int | None = None,
    ) -> None:
        if message_id:
            try:
                await client.edit_message_text(
                    chat_id,
                    message_id,
                    text,
                    reply_markup=reply_markup,
                )
                return
            except TelegramAPIError:
                pass
        await client.send_message(chat_id, text, reply_markup=reply_markup)

    async def send_center(chat_id: int, user_id: int, message_id: int | None = None) -> None:
        settings = prefs.get_user_settings(user_id)
        packs = prefs.get_user_packs(user_id)
        summary = usage.get_user_summary(user_id)
        link = usage.invite_link(bot_username, user_id)
        external_links = usage.get_external_links()
        await edit_or_send(
            chat_id=chat_id,
            text=user_center_text(user_id, settings, packs, summary, link, external_links),
            reply_markup=center_keyboard(user_id, settings, external_links),
            message_id=message_id,
        )

    async def send_quota(chat_id: int, user_id: int, message_id: int | None = None) -> None:
        summary = usage.get_user_summary(user_id)
        link = usage.invite_link(bot_username, user_id)
        await edit_or_send(
            chat_id=chat_id,
            text=quota_panel_text(summary, link),
            reply_markup={"inline_keyboard": [[_btn("🔙 返回中心", "ctr:refresh")]]},
            message_id=message_id,
        )

    async def send_recent(chat_id: int, user_id: int, message_id: int | None = None) -> None:
        summary = usage.get_user_summary(user_id)
        await edit_or_send(
            chat_id=chat_id,
            text=recent_panel_text(summary),
            reply_markup={"inline_keyboard": [[_btn("🔙 返回中心", "ctr:refresh")]]},
            message_id=message_id,
        )

    async def send_settings(chat_id: int, user_id: int, message_id: int | None = None) -> None:
        settings = prefs.get_user_settings(user_id)
        await edit_or_send(
            chat_id=chat_id,
            text=settings_panel_text(settings),
            reply_markup=settings_keyboard(),
            message_id=message_id,
        )

    async def send_packs(chat_id: int, user_id: int, message_id: int | None = None) -> None:
        settings = prefs.get_user_settings(user_id)
        packs = prefs.get_user_packs(user_id)
        current_pack_short = str(settings.get("current_pack_short") or "").strip()
        await edit_or_send(
            chat_id=chat_id,
            text=packs_panel_text(packs, current_pack_short),
            reply_markup=packs_keyboard(packs, current_pack_short),
            message_id=message_id,
        )

    async def send_invite_card(chat_id: int, user_id: int) -> None:
        policy = usage.get_policy()
        link = usage.invite_link(bot_username, user_id)
        card = generate_invite_card(
            invite_link=link,
            user_id=user_id,
            reward_clone=int(policy.get("invite_reward_clone", 0)),
            reward_make=int(policy.get("invite_reward_make", 0)),
        )
        caption = (
            f"邀请好友奖励: 克隆+{int(policy.get('invite_reward_clone', 0))}，"
            f"制作+{int(policy.get('invite_reward_make', 0))}\n{link}"
        )
        await client.send_photo(chat_id, card, caption=caption)

    async def send_admin_panel(chat_id: int, message_id: int | None = None) -> None:
        stats = usage.get_global_stats()
        await edit_or_send(
            chat_id=chat_id,
            text=f"{admin_help_text()}\n\n{admin_stats_text(stats)}",
            reply_markup=admin_home_keyboard(),
            message_id=message_id,
        )

    async def send_admin_links_panel(chat_id: int, message_id: int | None = None) -> None:
        links = usage.get_external_links()
        await edit_or_send(
            chat_id=chat_id,
            text=external_links_text(links),
            reply_markup=admin_links_keyboard(),
            message_id=message_id,
        )

    async def send_admin_audit_panel(
        chat_id: int,
        *,
        limit: int = 25,
        message_id: int | None = None,
    ) -> None:
        rows = audit.recent(limit=max(1, min(100, int(limit))))
        await edit_or_send(
            chat_id=chat_id,
            text=admin_audit_text(rows),
            reply_markup=admin_home_keyboard(),
            message_id=message_id,
        )

    async def send_admin_health_panel(chat_id: int, message_id: int | None = None) -> None:
        await edit_or_send(
            chat_id=chat_id,
            text=runtime_health_text(),
            reply_markup=admin_home_keyboard(),
            message_id=message_id,
        )

    async def send_admin_search_results(
        chat_id: int,
        query: str,
        *,
        message_id: int | None = None,
    ) -> None:
        keyword, filters = parse_admin_find_query(query)
        items = filter_users_for_admin(
            usage.list_all_users(),
            keyword=keyword,
            filters=filters,
            limit=20,
        )
        await edit_or_send(
            chat_id=chat_id,
            text=admin_search_results_text(query, items),
            reply_markup=admin_search_keyboard(items),
            message_id=message_id,
        )

    async def send_admin_user_detail(chat_id: int, target_user_id: int, message_id: int | None = None) -> None:
        usage_detail = usage.get_user_detail(target_user_id)
        settings = prefs.get_user_settings(target_user_id)
        packs = prefs.get_user_packs(target_user_id)
        await edit_or_send(
            chat_id=chat_id,
            text=admin_user_detail_text(target_user_id, usage_detail, settings, packs),
            reply_markup=admin_detail_keyboard(target_user_id),
            message_id=message_id,
        )

    def _retry_after_seconds(exc: Exception) -> int | None:
        msg = str(exc)
        m = re.search(r"retry after (\d+)", msg, flags=re.IGNORECASE)
        if not m:
            return None
        try:
            return max(1, int(m.group(1)))
        except ValueError:
            return None

    def is_transient_error(exc: Exception) -> bool:
        err_lower = str(exc).lower()
        return any(
            token in err_lower
            for token in ["network error", "timed out", "timeout", "temporarily", "too many requests", "try again later"]
        )

    async def _send_message_with_retry(chat_id: int, text: str, max_attempts: int = 4) -> bool:
        for attempt in range(max(1, int(max_attempts))):
            try:
                await client.send_message(chat_id, text)
                return True
            except TelegramAPIError as exc:
                retry_after = _retry_after_seconds(exc)
                if retry_after is not None and attempt + 1 < max_attempts:
                    await asyncio.sleep(retry_after + 1)
                    continue
                if is_transient_error(exc) and attempt + 1 < max_attempts:
                    await asyncio.sleep(1.2 * (attempt + 1))
                    continue
                return False
        return False

    async def run_broadcast(sender_chat_id: int, sender_user_id: int, text: str) -> None:
        msg = text.strip()
        if not msg:
            await client.send_message(sender_chat_id, "群发内容不能为空。")
            return
        user_ids = usage.get_all_user_ids()
        if not user_ids:
            await client.send_message(sender_chat_id, "暂无用户可群发。")
            return

        if broadcast_lock.locked():
            await client.send_message(sender_chat_id, "已有群发任务进行中，请稍后。")
            return

        async with broadcast_lock:
            total = len(user_ids)
            success = 0
            failed = 0
            admin_log(
                sender_user_id,
                "broadcast_start",
                f"开始群发，目标={total}",
                extra={"total": total},
            )
            await client.send_message(sender_chat_id, f"开始群发，目标用户: {total}")
            for idx, uid in enumerate(user_ids, start=1):
                ok = await _send_message_with_retry(uid, msg, max_attempts=4)
                if ok:
                    success += 1
                else:
                    failed += 1
                if idx % 50 == 0:
                    await client.send_message(sender_chat_id, f"群发进度: {idx}/{total}, 成功={success}, 失败={failed}")
                await asyncio.sleep(0.03)

            admin_log(
                sender_user_id,
                "broadcast_finish",
                f"群发完成 total={total} 成功={success} 失败={failed}",
                extra={"total": total, "success": success, "failed": failed},
            )
            await client.send_message(
                sender_chat_id,
                f"群发完成: total={total}, 成功={success}, 失败={failed}",
            )

    async def send_help_panel(chat_id: int, message_id: int | None = None) -> None:
        await edit_or_send(
            chat_id=chat_id,
            text=serve_help_text(bot_username),
            reply_markup=help_keyboard(),
            message_id=message_id,
        )

    async def send_help_full_panel(chat_id: int, message_id: int | None = None) -> None:
        await edit_or_send(
            chat_id=chat_id,
            text=serve_help_full_text(bot_username),
            reply_markup=help_keyboard(),
            message_id=message_id,
        )

    async def send_mode_picker(chat_id: int, user_id: int, message_id: int | None = None) -> None:
        settings = prefs.get_user_settings(user_id)
        current = normalize_visual_mode(settings.get("mode"))
        await edit_or_send(
            chat_id=chat_id,
            text=(
                "🎨 选择视觉模式\n"
                "maker: 署名增强\n"
                "clean: 纯净\n"
                "brand: 品牌条\n"
                "circle: 圆形\n"
                "pixel: 像素风\n"
                "bw: 黑白"
            ),
            reply_markup=mode_keyboard(current),
            message_id=message_id,
        )

    async def send_fit_picker(chat_id: int, user_id: int, message_id: int | None = None) -> None:
        settings = prefs.get_user_settings(user_id)
        current = normalize_fit_mode(settings.get("fit_mode"))
        await edit_or_send(
            chat_id=chat_id,
            text="🧭 选择适配模式\n完整保留(contain)\n铺满裁切(cover)",
            reply_markup=fit_keyboard(current),
            message_id=message_id,
        )

    async def send_clone_picker(chat_id: int, user_id: int, message_id: int | None = None) -> None:
        settings = prefs.get_user_settings(user_id)
        current = normalize_clone_mode(settings.get("clone_mode"))
        await edit_or_send(
            chat_id=chat_id,
            text="🧪 选择克隆策略\n工作室重渲染(studio)\n尽量原样复制(copy)",
            reply_markup=clone_mode_keyboard(current),
            message_id=message_id,
        )

    async def ensure_quota(chat_id: int, user_id: int, action: str) -> bool:
        ok, _ = usage.consume(user_id, action)
        if ok:
            return True
        summary = usage.get_user_summary(user_id)
        policy = summary.get("policy", DEFAULT_USAGE_POLICY)
        link = usage.invite_link(bot_username, user_id)
        action_cn = "克隆" if action == "clone" else "制作"
        await client.send_message(
            chat_id,
            (
                f"{action_cn}次数已用完。\n"
                f"当前剩余: 克隆={int(summary.get('clone_left', 0))}, 制作={int(summary.get('make_left', 0))}\n"
                f"每日保底: 克隆≥{int(policy.get('daily_free_clone', 0))}, 制作≥{int(policy.get('daily_free_make', 0))}\n"
                f"邀请1位好友可获得: 克隆+{int(policy.get('invite_reward_clone', 0))}, 制作+{int(policy.get('invite_reward_make', 0))}\n"
                f"邀请链接: {link}\n发送 /invite 可获取邀请海报。"
            ),
        )
        return False

    async def run_make_workflow(
        *,
        chat_id: int,
        user_id: int,
        image_bytes: bytes,
        make_payload: str,
        force_new_pack: bool = False,
    ) -> None:
        lock = locks.setdefault(user_id, asyncio.Lock())
        if lock.locked():
            await client.send_message(chat_id, "你有任务正在执行，请稍后。")
            return

        if not await ensure_quota(chat_id, user_id, "make"):
            return

        async with sem:
            async with lock:
                max_attempts = 3
                for attempt in range(max_attempts):
                    try:
                        result = await handle_make_request(
                            client,
                            chat_id=chat_id,
                            user_id=user_id,
                            image_bytes=image_bytes,
                            request_text=make_payload,
                            bot_username=bot_username,
                            user_prefs=prefs,
                            force_new_pack=force_new_pack,
                        )
                        usage.log_action(
                            user_id,
                            "make",
                            f"{result.get('target_short_name', '?')} ({result.get('action', '')})",
                        )
                        runtime_stats["make_ok"] = int(runtime_stats.get("make_ok", 0)) + 1
                        return
                    except (TelegramAPIError, ValueError) as exc:
                        if isinstance(exc, TelegramAPIError) and is_transient_error(exc) and (attempt + 1 < max_attempts):
                            await client.send_message(chat_id, f"制作网络波动，自动重试 {attempt + 2}/{max_attempts} ...")
                            await asyncio.sleep(1.0 * (attempt + 1))
                            continue
                        usage.refund(user_id, "make", 1)
                        runtime_stats["make_fail"] = int(runtime_stats.get("make_fail", 0)) + 1
                        await client.send_message(chat_id, f"制作失败: {exc}")
                        return

    async def process_message(message: dict[str, Any]) -> None:
        chat = message.get("chat") or {}
        chat_id = int(chat.get("id", 0))
        try:
            if chat.get("type") != "private":
                await client.send_message(chat_id, "请私聊机器人使用。")
                return

            user = message.get("from") or {}
            user_id = int(user.get("id", 0))
            if user_id <= 0:
                return
            runtime_stats["messages_total"] = int(runtime_stats.get("messages_total", 0)) + 1
            if check_rate_limit(user_id):
                await client.send_message(chat_id, "请求过于频繁，请稍后再试。")
                return
            display_name = f"{user.get('first_name', '')} {user.get('last_name', '')}".strip()
            usage.ensure_user(user_id, username=user.get("username", ""), display_name=display_name)

            text = (message.get("text") or "").strip()
            caption = (message.get("caption") or "").strip()
            command, payload = parse_command(text)

            if text:
                if command in {"cancel", "esc"} and user_id in admin_input_state:
                    admin_input_state.pop(user_id, None)
                    await client.send_message(chat_id, "已取消当前后台输入流程。")
                    return
                if command in {"cancel", "esc"} and user_id in user_input_state:
                    user_input_state.pop(user_id, None)
                    await client.send_message(chat_id, "已取消当前输入流程。")
                    return
                if command in {"cancel", "esc"} and user_id in pending_make_choice:
                    pending_make_choice.pop(user_id, None)
                    await client.send_message(chat_id, "已取消本次图片制作选择。")
                    return

                if command and user_id in admin_input_state and is_admin(user_id):
                    admin_input_state.pop(user_id, None)
                if command and user_id in user_input_state and command not in {"settitle", "renametitle", "title"}:
                    user_input_state.pop(user_id, None)
                if command and user_id in pending_make_choice and command != "make":
                    pending_make_choice.pop(user_id, None)

                if command is None and is_admin(user_id):
                    state = get_admin_input_state(user_id, chat_id)
                else:
                    state = None
                if state:
                    mode = str(state.get("mode") or "")
                    if mode == "admin_search":
                        query = text.strip()
                        if not query:
                            await client.send_message(chat_id, "搜索词不能为空。")
                            keep_admin_input_state_alive(user_id)
                            return
                        admin_input_state.pop(user_id, None)
                        await send_admin_search_results(chat_id, query)
                        return
                    if mode == "admin_set_link":
                        field = str(state.get("field") or "").strip()
                        if field not in {"group", "author"}:
                            admin_input_state.pop(user_id, None)
                            await client.send_message(chat_id, "设置状态已失效，请重新点击按钮。")
                            return
                        try:
                            value = normalize_external_link(text.strip())
                        except ValueError:
                            await client.send_message(
                                chat_id,
                                "链接格式不正确，请发送 https://... 或 @username（发送 /cancel 可取消）。",
                            )
                            keep_admin_input_state_alive(user_id)
                            return
                        admin_input_state.pop(user_id, None)
                        links = usage.update_external_links({field: value})
                        admin_log(
                            user_id,
                            "set_external_link",
                            f"{field}={value}",
                        )
                        await client.send_message(
                            chat_id,
                            "已更新外链设置。",
                            reply_markup=admin_links_keyboard(),
                        )
                        await client.send_message(
                            chat_id,
                            external_links_text(links),
                            reply_markup=admin_links_keyboard(),
                        )
                        return
                    if mode == "admin_quota_delta":
                        target_uid = int(state.get("target_uid", 0))
                        if target_uid <= 0:
                            admin_input_state.pop(user_id, None)
                            await client.send_message(chat_id, "目标用户无效。")
                            return
                        try:
                            updates = parse_admin_quota_delta_updates(text.strip())
                        except ValueError:
                            await client.send_message(chat_id, "格式错误。示例: 克隆=+3 制作=-1")
                            keep_admin_input_state_alive(user_id)
                            return
                        if not updates:
                            await client.send_message(chat_id, "请发送 克隆=+N 制作=+M（也支持 clone/make）。")
                            keep_admin_input_state_alive(user_id)
                            return
                        admin_input_state.pop(user_id, None)
                        summary = usage.adjust_user_quota(
                            target_uid,
                            clone_delta=updates.get("clone", 0),
                            make_delta=updates.get("make", 0),
                        )
                        admin_log(
                            user_id,
                            "adjust_user_quota",
                            f"clone_delta={updates.get('clone', 0)}, make_delta={updates.get('make', 0)}",
                            target_user_id=target_uid,
                        )
                        await client.send_message(
                            chat_id,
                            (
                                f"已调整用户 {target_uid}:\n"
                                f"克隆剩余={int(summary.get('clone_left', 0))}\n"
                                f"制作剩余={int(summary.get('make_left', 0))}"
                            ),
                        )
                        await send_admin_user_detail(chat_id, target_uid)
                        return

                if command is None:
                    ustate = get_user_input_state(user_id, chat_id)
                else:
                    ustate = None
                if ustate:
                    mode = str(ustate.get("mode") or "")
                    if mode == "user_set_pack_title":
                        target_short = str(ustate.get("target_short_name") or "").strip()
                        title = text.strip()
                        if not target_short:
                            user_input_state.pop(user_id, None)
                            await client.send_message(chat_id, "当前包无效，请重新进入设置。")
                            return
                        if not title:
                            await client.send_message(chat_id, "标题不能为空，请重新发送。")
                            keep_user_input_state_alive(user_id)
                            return
                        if len(title) > 64:
                            await client.send_message(chat_id, "标题太长，最多 64 个字符。")
                            keep_user_input_state_alive(user_id)
                            return
                        try:
                            await client.call("setStickerSetTitle", {"name": target_short, "title": title})
                        except TelegramAPIError as exc:
                            await client.send_message(chat_id, f"修改失败: {exc}")
                            keep_user_input_state_alive(user_id)
                            return
                        server_title = title
                        try:
                            s = await client.call("getStickerSet", {"name": target_short})
                            got = str(s.get("title") or "").strip()
                            if got:
                                server_title = got
                        except TelegramAPIError:
                            pass
                        user_input_state.pop(user_id, None)
                        settings = prefs.get_user_settings(user_id)
                        current_short = str(settings.get("current_pack_short") or "").strip()
                        if current_short == target_short:
                            prefs.set_user_pref(user_id, "current_pack_title", title)
                        prefs.touch_pack(user_id=user_id, short_name=target_short, title=title, count_add=0)
                        await client.send_message(
                            chat_id,
                            (
                                f"标题已更新: {title}\n"
                                f"服务器当前标题: {server_title}\n"
                                f"https://t.me/addstickers/{target_short}"
                            ),
                        )
                        await send_center(chat_id, user_id)
                        return

                if command == "start":
                    if payload.strip():
                        ok, msg, extra = usage.apply_referral(
                            user_id,
                            payload.strip(),
                            new_username=user.get("username", ""),
                            new_display_name=display_name,
                        )
                        await client.send_message(chat_id, msg)
                        if ok and extra.get("inviter_id"):
                            inviter_id = int(extra.get("inviter_id", 0))
                            if inviter_id > 0:
                                try:
                                    await client.send_message(
                                        inviter_id,
                                        (
                                            f"你邀请了新用户 {display_name or user.get('username') or user_id}，"
                                            f"获得 clone+{int(extra.get('reward_clone', 0))} / "
                                            f"make+{int(extra.get('reward_make', 0))} 次。"
                                        ),
                                    )
                                except TelegramAPIError:
                                    pass
                    await client.send_message(chat_id, serve_welcome_text(bot_username))
                    await send_center(chat_id, user_id)
                    return

                if command == "help":
                    await send_help_panel(chat_id)
                    return

                if command == "helpall":
                    await send_help_full_panel(chat_id)
                    return

                if command == "me":
                    await client.send_message(chat_id, f"你的用户ID: {user_id}")
                    return

                if command == "modes":
                    await client.send_message(chat_id, serve_modes_text())
                    return

                if command in {"profile", "center", "my", "menu"}:
                    await send_center(chat_id, user_id)
                    return

                if command in {"invite", "share"}:
                    link = usage.invite_link(bot_username, user_id)
                    policy = usage.get_policy()
                    await client.send_message(
                        chat_id,
                        (
                            f"邀请链接: {link}\n"
                            f"每邀请1人奖励: 克隆+{int(policy.get('invite_reward_clone', 0))}，"
                            f"制作+{int(policy.get('invite_reward_make', 0))}"
                        ),
                    )
                    await send_invite_card(chat_id, user_id)
                    return

                if command in {"invitecard", "card"}:
                    await send_invite_card(chat_id, user_id)
                    return

                if command == "quota":
                    await send_quota(chat_id, user_id)
                    return

                if command in {"admin", "adminpanel"}:
                    if user_id not in admin_user_ids:
                        await client.send_message(chat_id, "无权限。")
                        return
                    await send_admin_panel(chat_id)
                    return

                if command in {"adminstats", "astats"}:
                    if user_id not in admin_user_ids:
                        await client.send_message(chat_id, "无权限。")
                        return
                    await client.send_message(
                        chat_id,
                        admin_stats_text(usage.get_global_stats()),
                        reply_markup=admin_home_keyboard(),
                    )
                    return

                if command in {"adminaudit", "aaudit"}:
                    if user_id not in admin_user_ids:
                        await client.send_message(chat_id, "无权限。")
                        return
                    limit = 25
                    if payload.strip():
                        try:
                            limit = max(1, min(100, int(payload.strip().split()[0])))
                        except ValueError:
                            await client.send_message(chat_id, "用法: /adminaudit [条数]")
                            return
                    await send_admin_audit_panel(chat_id, limit=limit)
                    return

                if command in {"adminusers", "ausers"}:
                    if user_id not in admin_user_ids:
                        await client.send_message(chat_id, "无权限。")
                        return
                    page = 1
                    if payload.strip():
                        try:
                            page = max(1, int(payload.strip().split()[0]))
                        except ValueError:
                            await client.send_message(chat_id, "用法: /adminusers [page]")
                            return
                    page_data = usage.list_users(page=page, page_size=20)
                    await client.send_message(
                        chat_id,
                        admin_users_page_text(page_data),
                        reply_markup=admin_users_keyboard(page_data),
                    )
                    return

                if command in {"adminfind", "afind"}:
                    if user_id not in admin_user_ids:
                        await client.send_message(chat_id, "无权限。")
                        return
                    query = payload.strip()
                    if not query:
                        await client.send_message(
                            chat_id,
                            "用法: /adminfind <关键词> [uid:123 active:true min_clone_done:5]",
                        )
                        return
                    keyword, filters = parse_admin_find_query(query)
                    items = filter_users_for_admin(
                        usage.list_all_users(),
                        keyword=keyword,
                        filters=filters,
                        limit=20,
                    )
                    await client.send_message(
                        chat_id,
                        admin_search_results_text(query, items),
                        reply_markup=admin_search_keyboard(items),
                    )
                    return

                if command in {"adminexport", "aexport"}:
                    if user_id not in admin_user_ids:
                        await client.send_message(chat_id, "无权限。")
                        return
                    query = payload.strip()
                    keyword, filters = parse_admin_find_query(query)
                    items = filter_users_for_admin(
                        usage.list_all_users(),
                        keyword=keyword,
                        filters=filters,
                        limit=5000,
                    )
                    if not items:
                        await client.send_message(chat_id, "没有可导出的用户数据。")
                        return
                    data = users_csv_bytes(items)
                    ts = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
                    await client.send_document(
                        chat_id,
                        data,
                        filename=f"users_{ts}.csv",
                        caption=f"导出完成，共 {len(items)} 条",
                    )
                    return

                if command in {"adminhealth", "ahealth"}:
                    if user_id not in admin_user_ids:
                        await client.send_message(chat_id, "无权限。")
                        return
                    await client.send_message(chat_id, runtime_health_text(), reply_markup=admin_home_keyboard())
                    return

                if command in {"adminuser", "auser"}:
                    if user_id not in admin_user_ids:
                        await client.send_message(chat_id, "无权限。")
                        return
                    if not payload.strip():
                        await client.send_message(chat_id, "用法: /adminuser <用户ID>")
                        return
                    try:
                        target_uid = int(payload.strip().split()[0])
                    except ValueError:
                        await client.send_message(chat_id, "用户ID必须是整数。")
                        return
                    await send_admin_user_detail(chat_id, target_uid)
                    return

                if command in {"adminbroadcast", "abroadcast"}:
                    if user_id not in admin_user_ids:
                        await client.send_message(chat_id, "无权限。")
                        return
                    if not payload.strip():
                        await client.send_message(chat_id, "用法: /adminbroadcast <群发内容>")
                        return
                    await run_broadcast(chat_id, user_id, payload)
                    return

                if command in {"adminpolicy", "apolicy"}:
                    if user_id not in admin_user_ids:
                        await client.send_message(chat_id, "无权限。")
                        return
                    if not payload.strip():
                        await client.send_message(
                            chat_id,
                            policy_text(usage.get_policy()),
                            reply_markup=admin_home_keyboard(),
                        )
                        return
                    try:
                        updates = parse_policy_updates(payload)
                    except ValueError:
                        await client.send_message(chat_id, "参数格式错误。示例: /adminpolicy free_clone=2 invite_reward_make=3")
                        return
                    if not updates:
                        await client.send_message(
                            chat_id,
                            (
                                "未识别到可更新参数。可用: free_clone free_make "
                                "invite_reward_clone invite_reward_make enforce_limits "
                                "daily_reset_enabled daily_free_clone daily_free_make"
                            ),
                        )
                        return
                    old_policy = usage.get_policy()
                    policy = usage.update_policy(updates)
                    admin_log(
                        user_id,
                        "update_policy",
                        f"keys={','.join(sorted(updates.keys()))}",
                        extra={"updates": updates, "before": old_policy, "after": policy},
                    )
                    await client.send_message(chat_id, policy_text(policy), reply_markup=admin_home_keyboard())
                    return

                if command in {"adminquota", "aquota"}:
                    if user_id not in admin_user_ids:
                        await client.send_message(chat_id, "无权限。")
                        return
                    if not payload.strip():
                        await client.send_message(chat_id, "用法: /adminquota <用户ID> clone=<n> make=<n>")
                        return
                    try:
                        target_uid, updates = parse_admin_quota_payload(payload)
                    except ValueError:
                        await client.send_message(chat_id, "参数格式错误。示例: /adminquota 123456 clone=10 make=8")
                        return
                    if not updates:
                        await client.send_message(chat_id, "至少提供 clone=<n> 或 make=<n>")
                        return
                    summary = usage.set_user_quota(
                        target_uid,
                        clone_left=updates.get("clone"),
                        make_left=updates.get("make"),
                    )
                    admin_log(
                        user_id,
                        "set_user_quota",
                        f"clone={updates.get('clone', '-')}, make={updates.get('make', '-')}",
                        target_user_id=target_uid,
                    )
                    await client.send_message(
                        chat_id,
                        (
                            f"已更新用户 {target_uid} 配额:\n"
                            f"克隆剩余={int(summary.get('clone_left', 0))}\n"
                            f"制作剩余={int(summary.get('make_left', 0))}"
                        ),
                    )
                    return

                if command in {"adminlinks", "alinks"}:
                    if user_id not in admin_user_ids:
                        await client.send_message(chat_id, "无权限。")
                        return
                    if not payload.strip():
                        await client.send_message(
                            chat_id,
                            external_links_text(usage.get_external_links()),
                            reply_markup=admin_links_keyboard(),
                        )
                        return
                    try:
                        updates = parse_admin_links_updates(payload)
                    except ValueError:
                        await client.send_message(
                            chat_id,
                            "参数格式错误。建议直接使用“外链设置”按钮配置。",
                            reply_markup=admin_links_keyboard(),
                        )
                        return
                    if not updates:
                        await client.send_message(
                            chat_id,
                            "未识别到可更新参数。建议直接使用“外链设置”按钮配置。",
                            reply_markup=admin_links_keyboard(),
                        )
                        return
                    links = usage.update_external_links(updates)
                    admin_log(
                        user_id,
                        "set_external_links",
                        " ".join([f"{k}={v}" for k, v in updates.items()]),
                        extra={"updates": updates},
                    )
                    await client.send_message(chat_id, external_links_text(links), reply_markup=admin_links_keyboard())
                    return

                if command in {"setwm", "setmaker", "setsign"}:
                    wm = payload.strip()
                    if not wm:
                        await client.send_message(chat_id, "用法: /setmaker @你的署名")
                        return
                    prefs.set_user_pref(user_id, "watermark", wm)
                    await client.send_message(chat_id, f"默认制作人署名已设置: {wm}")
                    return

                if command in {"clearwm", "clearmaker", "clearsign"}:
                    prefs.set_user_pref(user_id, "watermark", None)
                    await client.send_message(chat_id, "默认制作人署名已清空。")
                    return

                if command == "setmode":
                    raw_mode = payload.strip().lower()
                    if raw_mode not in VISUAL_MODES:
                        await client.send_message(chat_id, f"无效视觉模式。可用: {', '.join(sorted(VISUAL_MODES))}")
                        return
                    mode = normalize_visual_mode(raw_mode)
                    prefs.set_user_pref(user_id, "mode", mode)
                    await client.send_message(chat_id, f"默认视觉模式已设置: {visual_mode_label(mode)}")
                    await send_settings(chat_id, user_id)
                    return

                if command == "setfit":
                    raw_fit = payload.strip().lower()
                    if raw_fit not in FIT_MODES:
                        await client.send_message(chat_id, f"无效适配模式。可用: {', '.join(sorted(FIT_MODES))}")
                        return
                    fit_mode = normalize_fit_mode(raw_fit)
                    prefs.set_user_pref(user_id, "fit_mode", fit_mode)
                    await client.send_message(chat_id, f"默认适配模式已设置: {fit_mode_label(fit_mode)}")
                    await send_settings(chat_id, user_id)
                    return

                if command == "setclonemode":
                    raw_clone = payload.strip().lower()
                    if raw_clone not in CLONE_MODES:
                        await client.send_message(chat_id, f"无效克隆策略。可用: {', '.join(sorted(CLONE_MODES))}")
                        return
                    clone_mode = normalize_clone_mode(raw_clone)
                    prefs.set_user_pref(user_id, "clone_mode", clone_mode)
                    await client.send_message(chat_id, f"默认克隆策略已设置: {clone_mode_label(clone_mode)}")
                    await send_settings(chat_id, user_id)
                    return

                if command in {"setmaketarget", "setmake", "maketarget"}:
                    raw_target = payload.strip().lower()
                    if raw_target not in MAKE_TARGET_MODE_LABELS:
                        await client.send_message(chat_id, "无效发图去向。可用: ask, join, new")
                        return
                    target_mode = normalize_make_target_mode(raw_target)
                    prefs.set_user_pref(user_id, "make_target_mode", target_mode)
                    await client.send_message(chat_id, f"发图默认去向已设置: {make_target_mode_label(target_mode)}")
                    await send_settings(chat_id, user_id)
                    return

                if command in {"settitle", "renametitle", "title"}:
                    try:
                        input_short, new_title = parse_settitle_payload(payload)
                    except ValueError as exc:
                        await client.send_message(
                            chat_id,
                            f"{exc}\n用法: /settitle 新标题\n或: /settitle 包短名|链接 | 新标题",
                        )
                        return
                    target_short = (input_short or "").strip()
                    if not target_short:
                        settings = prefs.get_user_settings(user_id)
                        target_short = str(settings.get("current_pack_short") or "").strip()
                    if not target_short:
                        await client.send_message(chat_id, "你还没有当前包。先克隆或制作一个包，再修改标题。")
                        return
                    if len(new_title) > 64:
                        await client.send_message(chat_id, "标题太长，最多 64 个字符。")
                        return
                    try:
                        await client.call("setStickerSetTitle", {"name": target_short, "title": new_title})
                    except TelegramAPIError as exc:
                        await client.send_message(chat_id, f"修改失败: {exc}")
                        return
                    server_title = new_title
                    try:
                        s = await client.call("getStickerSet", {"name": target_short})
                        got = str(s.get("title") or "").strip()
                        if got:
                            server_title = got
                    except TelegramAPIError:
                        pass
                    settings = prefs.get_user_settings(user_id)
                    current_short = str(settings.get("current_pack_short") or "").strip()
                    if current_short == target_short:
                        prefs.set_user_pref(user_id, "current_pack_title", new_title)
                    prefs.touch_pack(user_id=user_id, short_name=target_short, title=new_title, count_add=0)
                    await client.send_message(
                        chat_id,
                        (
                            f"标题已更新: {new_title}\n"
                            f"服务器当前标题: {server_title}\n"
                            f"https://t.me/addstickers/{target_short}"
                        ),
                    )
                    await send_center(chat_id, user_id)
                    return

                if command == "setpack":
                    parts = [x.strip() for x in payload.split("|")]
                    short_name = parts[0] if parts and parts[0] else ""
                    title = parts[1] if len(parts) > 1 and parts[1] else ""
                    if not short_name and not title:
                        await client.send_message(chat_id, "用法: /setpack 包短名 | 包标题")
                        return
                    if short_name:
                        prefs.set_user_pref(user_id, "current_pack_short", short_name)
                    if title:
                        prefs.set_user_pref(user_id, "current_pack_title", title)
                    if short_name:
                        prefs.touch_pack(user_id=user_id, short_name=short_name, title=title or None, count_add=0)
                    await client.send_message(chat_id, "当前包已设置。后续发图片会继续添加到这个包。")
                    await send_center(chat_id, user_id)
                    return

                if command == "usepack":
                    parts = [x.strip() for x in payload.split("|")]
                    short_name = parts[0] if parts and parts[0] else ""
                    title = parts[1] if len(parts) > 1 and parts[1] else ""
                    if not short_name:
                        await client.send_message(chat_id, "用法: /usepack 包短名 | 包标题(可选)")
                        return
                    prefs.set_user_pref(user_id, "current_pack_short", short_name)
                    if title:
                        prefs.set_user_pref(user_id, "current_pack_title", title)
                    prefs.touch_pack(user_id=user_id, short_name=short_name, title=title or None, count_add=0)
                    await client.send_message(chat_id, f"已切换到当前包: {short_name}")
                    await send_center(chat_id, user_id)
                    return

                if command == "packlist":
                    packs = prefs.get_user_packs(user_id)
                    if not packs:
                        await client.send_message(chat_id, "最近包为空。先发一张图片制作贴纸。")
                        return
                    lines = ["最近包:"]
                    for idx, item in enumerate(packs[:8], start=1):
                        lines.append(
                            f"{idx}. {(item.get('title') or item.get('short_name'))} ({item.get('short_name')}) x{int(item.get('count', 0))}"
                        )
                    await client.send_message(chat_id, "\n".join(lines))
                    return

                if command == "clearpack":
                    prefs.set_user_pref(user_id, "current_pack_short", None)
                    prefs.set_user_pref(user_id, "current_pack_title", None)
                    await client.send_message(chat_id, "当前包已清空。")
                    await send_center(chat_id, user_id)
                    return

                if command == "make":
                    await client.send_message(
                        chat_id,
                        "请发送图片，并在图片标题写 /make 参数。示例: /make 😀 | 包标题 | 包短名 | @署名 | maker | contain",
                    )
                    return

                lock = locks.setdefault(user_id, asyncio.Lock())
                if lock.locked():
                    await client.send_message(chat_id, "你有任务正在执行，请稍后。")
                    return

                req_text = payload if command == "clone" else text
                if command and command not in {"clone"}:
                    await client.send_message(chat_id, "不支持该命令，发送 /help 查看用法。")
                    return

                if command is None:
                    if text in {"个人中心", "中心", "我的", "我的中心", "菜单", "按钮菜单"}:
                        await send_center(chat_id, user_id)
                        return
                    if text in {"管理员后台", "后台", "admin"}:
                        if user_id not in admin_user_ids:
                            await client.send_message(chat_id, "无权限。")
                            return
                        await send_admin_panel(chat_id)
                        return
                    if text in {"邀请", "邀请好友", "拉新"}:
                        link = usage.invite_link(bot_username, user_id)
                        policy = usage.get_policy()
                        await client.send_message(
                            chat_id,
                            (
                                f"邀请链接: {link}\n"
                                f"每邀请1人奖励: 克隆+{int(policy.get('invite_reward_clone', 0))}，"
                                f"制作+{int(policy.get('invite_reward_make', 0))}"
                            ),
                        )
                        await send_invite_card(chat_id, user_id)
                        return
                    try:
                        extract_sticker_set_name(req_text)
                    except ValueError:
                        await client.send_message(chat_id, "发我表情包链接，或发图片自动制作贴纸。")
                        return

                if not await ensure_quota(chat_id, user_id, "clone"):
                    return

                async with sem:
                    async with lock:
                        max_attempts = 3
                        for attempt in range(max_attempts):
                            try:
                                result = await handle_clone_request(
                                    client,
                                    chat_id=chat_id,
                                    user_id=user_id,
                                    request_text=req_text,
                                    bot_username=bot_username,
                                    user_prefs=prefs,
                                    progress_step=args.progress_step,
                                )
                                usage.log_action(
                                    user_id,
                                    "clone",
                                    f"{result.get('source_name', '?')} -> {result.get('target_short_name', '?')}",
                                )
                                prefs.touch_pack(
                                    user_id=user_id,
                                    short_name=str(result.get("target_short_name", "")).strip(),
                                    title=str(result.get("target_title", "")).strip() or None,
                                    count_add=0,
                                )
                                runtime_stats["clone_ok"] = int(runtime_stats.get("clone_ok", 0)) + 1
                                break
                            except (TelegramAPIError, ValueError) as exc:
                                if isinstance(exc, TelegramAPIError) and is_transient_error(exc) and (attempt + 1 < max_attempts):
                                    await client.send_message(chat_id, f"克隆网络波动，自动重试 {attempt + 2}/{max_attempts} ...")
                                    await asyncio.sleep(1.0 * (attempt + 1))
                                    continue
                                usage.refund(user_id, "clone", 1)
                                runtime_stats["clone_fail"] = int(runtime_stats.get("clone_fail", 0)) + 1
                                await client.send_message(chat_id, f"任务失败: {exc}")
                                break
                return

            image_bytes = await extract_image_bytes_from_message(client, message)
            if image_bytes is None:
                return

            caption_command, caption_payload = parse_command(caption)
            make_payload = ""
            if caption:
                if caption_command and caption_command not in {"make"}:
                    await client.send_message(chat_id, "图片标题命令仅支持 /make。")
                    return
                make_payload = caption_payload if caption_command == "make" else caption

            if not make_payload.strip():
                settings = prefs.get_user_settings(user_id)
                current_short = str(settings.get("current_pack_short") or "").strip()
                make_target = normalize_make_target_mode(settings.get("make_target_mode"))
                if current_short and make_target == "ask":
                    set_pending_make_choice(user_id, chat_id, image_bytes, make_payload)
                    await client.send_message(
                        chat_id,
                        (
                            "本次图片制作请选择去向：\n"
                            f"当前包: {current_short}\n"
                            "可加入当前包，或新建一个表情包。"
                        ),
                        reply_markup=make_choice_keyboard(current_short),
                    )
                    return
                if make_target == "new":
                    pending_make_choice.pop(user_id, None)
                    await run_make_workflow(
                        chat_id=chat_id,
                        user_id=user_id,
                        image_bytes=image_bytes,
                        make_payload=make_payload,
                        force_new_pack=True,
                    )
                    return

            pending_make_choice.pop(user_id, None)
            await run_make_workflow(
                chat_id=chat_id,
                user_id=user_id,
                image_bytes=image_bytes,
                make_payload=make_payload,
                force_new_pack=False,
            )
        except TelegramAPIError as exc:
            console.print(f"服务任务错误: {exc}", style="red")
        except Exception as exc:
            console.print(f"服务出现未预期错误: {exc}", style="red")

    async def process_callback(callback_query: dict[str, Any]) -> None:
        try:
            cb_id = str(callback_query.get("id") or "")
            data = str(callback_query.get("data") or "").strip()
            message = callback_query.get("message") or {}
            chat = message.get("chat") or {}
            chat_id = int(chat.get("id", 0))
            message_id = int(message.get("message_id", 0))
            user = callback_query.get("from") or {}
            user_id = int(user.get("id", 0))
            if user_id <= 0:
                return
            runtime_stats["callbacks_total"] = int(runtime_stats.get("callbacks_total", 0)) + 1

            async def ack(text: str | None = None) -> None:
                if not cb_id:
                    return
                try:
                    await client.answer_callback_query(cb_id, text=text)
                except TelegramAPIError:
                    pass

            if chat.get("type") != "private" or chat_id <= 0 or message_id <= 0:
                await ack("请私聊机器人使用")
                return

            display_name = f"{user.get('first_name', '')} {user.get('last_name', '')}".strip()
            usage.ensure_user(user_id, username=user.get("username", ""), display_name=display_name)

            if data == "ctr:refresh":
                await send_center(chat_id, user_id, message_id=message_id)
                await ack("已刷新")
                return

            if data == "ctr:quota":
                await send_quota(chat_id, user_id, message_id=message_id)
                await ack()
                return

            if data == "ctr:recent":
                await send_recent(chat_id, user_id, message_id=message_id)
                await ack()
                return

            if data == "ctr:packs":
                await send_packs(chat_id, user_id, message_id=message_id)
                await ack()
                return

            if data == "ctr:settings":
                await send_settings(chat_id, user_id, message_id=message_id)
                await ack()
                return

            if data == "ctr:help":
                await send_help_panel(chat_id, message_id=message_id)
                await ack()
                return

            if data == "ctr:helpall":
                await send_help_full_panel(chat_id, message_id=message_id)
                await ack()
                return

            if data == "ctr:invitecard":
                await ack("正在生成邀请海报...")
                await send_invite_card(chat_id, user_id)
                return

            if data in {"mkc:join", "mkc:new", "mkc:cancel"}:
                state = get_pending_make_choice(user_id, chat_id)
                if not state:
                    await ack("本次选择已过期，请重新发图")
                    return
                if data == "mkc:cancel":
                    pending_make_choice.pop(user_id, None)
                    await edit_or_send(
                        chat_id=chat_id,
                        text="已取消本次图片制作。",
                        reply_markup=center_keyboard(user_id, prefs.get_user_settings(user_id), usage.get_external_links()),
                        message_id=message_id,
                    )
                    await ack("已取消")
                    return

                pending_make_choice.pop(user_id, None)
                force_new = data == "mkc:new"
                raw_bytes = state.get("image_bytes")
                if not isinstance(raw_bytes, (bytes, bytearray)) or not raw_bytes:
                    await ack("图片数据已失效，请重新发送")
                    return
                await ack("已开始制作")
                await run_make_workflow(
                    chat_id=chat_id,
                    user_id=user_id,
                    image_bytes=bytes(raw_bytes),
                    make_payload=str(state.get("make_payload") or ""),
                    force_new_pack=force_new,
                )
                return

            if data == "set:mode":
                await send_mode_picker(chat_id, user_id, message_id=message_id)
                await ack()
                return

            if data == "set:fit":
                await send_fit_picker(chat_id, user_id, message_id=message_id)
                await ack()
                return

            if data == "set:clone":
                await send_clone_picker(chat_id, user_id, message_id=message_id)
                await ack()
                return

            if data == "set:maketarget":
                settings = prefs.get_user_settings(user_id)
                current = normalize_make_target_mode(settings.get("make_target_mode"))
                await edit_or_send(
                    chat_id=chat_id,
                    text="🖼 选择发图默认去向\nask: 每次询问\njoin: 默认加入当前包\nnew: 默认新建包",
                    reply_markup=make_target_keyboard(current),
                    message_id=message_id,
                )
                await ack()
                return

            if data.startswith("set:modev:"):
                mode = data.split(":", 2)[2].strip().lower()
                if mode not in VISUAL_MODES:
                    await ack("无效视觉模式")
                    return
                prefs.set_user_pref(user_id, "mode", normalize_visual_mode(mode))
                await send_settings(chat_id, user_id, message_id=message_id)
                await ack(f"视觉模式: {visual_mode_label(mode)}")
                return

            if data.startswith("set:fitv:"):
                fit_mode = data.split(":", 2)[2].strip().lower()
                if fit_mode not in FIT_MODES:
                    await ack("无效适配模式")
                    return
                prefs.set_user_pref(user_id, "fit_mode", normalize_fit_mode(fit_mode))
                await send_settings(chat_id, user_id, message_id=message_id)
                await ack(f"适配模式: {fit_mode_label(fit_mode)}")
                return

            if data.startswith("set:clonev:"):
                clone_mode = data.split(":", 2)[2].strip().lower()
                if clone_mode not in CLONE_MODES:
                    await ack("无效克隆策略")
                    return
                prefs.set_user_pref(user_id, "clone_mode", normalize_clone_mode(clone_mode))
                await send_settings(chat_id, user_id, message_id=message_id)
                await ack(f"克隆策略: {clone_mode_label(clone_mode)}")
                return

            if data.startswith("set:maketargetv:"):
                target_mode = data.split(":", 2)[2].strip().lower()
                if target_mode not in MAKE_TARGET_MODE_LABELS:
                    await ack("无效发图去向")
                    return
                prefs.set_user_pref(user_id, "make_target_mode", normalize_make_target_mode(target_mode))
                await send_settings(chat_id, user_id, message_id=message_id)
                await ack(f"发图去向: {make_target_mode_label(target_mode)}")
                return

            if data == "set:wmclear":
                prefs.set_user_pref(user_id, "watermark", None)
                await send_settings(chat_id, user_id, message_id=message_id)
                await ack("已清空制作人署名")
                return

            if data == "set:packclear":
                prefs.set_user_pref(user_id, "current_pack_short", None)
                prefs.set_user_pref(user_id, "current_pack_title", None)
                await send_settings(chat_id, user_id, message_id=message_id)
                await ack("已清空当前包")
                return

            if data == "set:title":
                settings = prefs.get_user_settings(user_id)
                current_short = str(settings.get("current_pack_short") or "").strip()
                if not current_short:
                    await ack("请先创建或选择当前包")
                    return
                set_user_input_state(user_id, chat_id, "user_set_pack_title", target_short_name=current_short)
                await edit_or_send(
                    chat_id=chat_id,
                    text=(
                        f"请发送新的包标题（当前包: {current_short}）。\n"
                        "最多 64 个字符。\n"
                        "发送 /cancel 取消。"
                    ),
                    reply_markup=settings_keyboard(),
                    message_id=message_id,
                )
                await ack("等待输入")
                return

            if data.startswith("pack:use:"):
                try:
                    idx = int(data.split(":", 2)[2].strip())
                except ValueError:
                    await ack("参数错误")
                    return
                packs = prefs.get_user_packs(user_id)
                if idx < 0 or idx >= len(packs):
                    await ack("该记录已失效，请刷新")
                    return
                item = packs[idx]
                short_name = str(item.get("short_name") or "").strip()
                title = str(item.get("title") or "").strip()
                if not short_name:
                    await ack("短名无效")
                    return
                prefs.set_user_pref(user_id, "current_pack_short", short_name)
                if title:
                    prefs.set_user_pref(user_id, "current_pack_title", title)
                prefs.touch_pack(user_id=user_id, short_name=short_name, title=title or None, count_add=0)
                await send_center(chat_id, user_id, message_id=message_id)
                await ack(f"已切换: {short_name}")
                return

            if data.startswith("adm:"):
                if not is_admin(user_id):
                    await ack("无权限")
                    return
                if data == "adm:home":
                    admin_input_state.pop(user_id, None)
                    await send_admin_panel(chat_id, message_id=message_id)
                    await ack()
                    return
                if data == "adm:stats":
                    await edit_or_send(
                        chat_id=chat_id,
                        text=admin_stats_text(usage.get_global_stats()),
                        reply_markup=admin_home_keyboard(),
                        message_id=message_id,
                    )
                    await ack()
                    return
                if data == "adm:health":
                    await send_admin_health_panel(chat_id, message_id=message_id)
                    await ack()
                    return
                if data == "adm:policy":
                    await edit_or_send(
                        chat_id=chat_id,
                        text=policy_text(usage.get_policy()),
                        reply_markup=admin_home_keyboard(),
                        message_id=message_id,
                    )
                    await ack()
                    return
                if data == "adm:audit":
                    await send_admin_audit_panel(chat_id, message_id=message_id)
                    await ack()
                    return
                if data == "adm:links":
                    await send_admin_links_panel(chat_id, message_id=message_id)
                    await ack()
                    return
                if data.startswith("adm:export:"):
                    mode = data.split(":", 2)[2].strip().lower()
                    if mode == "all":
                        items = usage.list_all_users()
                    else:
                        items = filter_users_for_admin(usage.list_all_users(), keyword=mode, filters={}, limit=5000)
                    if not items:
                        await ack("没有可导出的数据")
                        return
                    ts = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
                    await client.send_document(
                        chat_id,
                        users_csv_bytes(items),
                        filename=f"users_{ts}.csv",
                        caption=f"导出完成，共 {len(items)} 条",
                    )
                    await ack("已导出")
                    return
                if data in {"adm:link:set:group", "adm:link:set:author"}:
                    field = "group" if data.endswith("group") else "author"
                    set_admin_input_state(user_id, chat_id, "admin_set_link", field=field)
                    label = "交流群链接" if field == "group" else "作者联系方式"
                    await edit_or_send(
                        chat_id=chat_id,
                        text=(
                            f"请发送{label}。\n"
                            "支持: https://... 或 @username\n"
                            "发送 /cancel 取消。"
                        ),
                        reply_markup=admin_links_keyboard(),
                        message_id=message_id,
                    )
                    await ack("等待输入")
                    return
                if data in {"adm:link:clear:group", "adm:link:clear:author"}:
                    field = "group" if data.endswith("group") else "author"
                    usage.update_external_links({field: ""})
                    admin_log(user_id, "clear_external_link", f"{field}=clear")
                    await send_admin_links_panel(chat_id, message_id=message_id)
                    await ack("已清空")
                    return
                if data == "adm:search":
                    set_admin_input_state(user_id, chat_id, "admin_search")
                    await edit_or_send(
                        chat_id=chat_id,
                        text=(
                            "请输入搜索条件（关键词 + 可选过滤器）。\n"
                            "示例: 小明 active:true min_clone_done:5\n"
                            "支持: uid:123 active:true/false invited:true/false min_clone_done:N min_make_done:N min_invite:N\n"
                            "发送 /cancel 取消。"
                        ),
                        reply_markup=admin_home_keyboard(),
                        message_id=message_id,
                    )
                    await ack("请发送关键词")
                    return
                if data.startswith("adm:users:"):
                    try:
                        page = int(data.split(":", 2)[2].strip())
                    except ValueError:
                        page = 1
                    page_data = usage.list_users(page=max(1, page), page_size=10)
                    await edit_or_send(
                        chat_id=chat_id,
                        text=admin_users_page_text(page_data),
                        reply_markup=admin_users_keyboard(page_data),
                        message_id=message_id,
                    )
                    await ack()
                    return
                if data.startswith("adm:user:"):
                    try:
                        target_uid = int(data.split(":", 2)[2].strip())
                    except ValueError:
                        await ack("用户ID错误")
                        return
                    await send_admin_user_detail(chat_id, target_uid, message_id=message_id)
                    await ack()
                    return
                if data.startswith("adm:qinput:"):
                    try:
                        target_uid = int(data.split(":", 2)[2].strip())
                    except ValueError:
                        await ack("用户ID错误")
                        return
                    set_admin_input_state(user_id, chat_id, "admin_quota_delta", target_uid=target_uid)
                    await edit_or_send(
                        chat_id=chat_id,
                        text=(
                            f"请发送额度增减（用户 {target_uid}）。\n"
                            "示例: 克隆=+3 制作=-1（也支持 clone=+3 make=-1）\n"
                            "发送 /cancel 取消。"
                        ),
                        reply_markup=admin_detail_keyboard(target_uid),
                        message_id=message_id,
                    )
                    await ack("等待输入")
                    return
                if data.startswith("adm:q:"):
                    parts = data.split(":")
                    if len(parts) != 5:
                        await ack("参数错误")
                        return
                    try:
                        target_uid = int(parts[2])
                        action = parts[3].strip().lower()
                        delta = int(parts[4])
                    except ValueError:
                        await ack("参数错误")
                        return
                    if target_uid <= 0 or action not in {"clone", "make"}:
                        await ack("参数错误")
                        return
                    summary = usage.adjust_user_quota(
                        target_uid,
                        clone_delta=(delta if action == "clone" else 0),
                        make_delta=(delta if action == "make" else 0),
                    )
                    admin_log(
                        user_id,
                        "adjust_user_quota",
                        f"{action}_delta={delta}",
                        target_user_id=target_uid,
                    )
                    await send_admin_user_detail(chat_id, target_uid, message_id=message_id)
                    await ack(
                        f"已更新: 克隆={int(summary.get('clone_left', 0))}, 制作={int(summary.get('make_left', 0))}"
                    )
                    return

            await ack("按钮已过期，发送 /center 重新打开")
        except TelegramAPIError as exc:
            console.print(f"服务回调错误: {exc}", style="red")
        except Exception as exc:
            console.print(f"服务回调未预期错误: {exc}", style="red")

    async def process_update(update: dict[str, Any], *, from_polling: bool) -> None:
        nonlocal offset
        runtime_stats["updates_total"] = int(runtime_stats.get("updates_total", 0)) + 1
        if from_polling and "update_id" in update:
            try:
                offset = max(offset, int(update["update_id"]) + 1)
            except (TypeError, ValueError):
                pass
        message = update.get("message") or {}
        callback_query = update.get("callback_query") or {}
        if message:
            task = asyncio.create_task(process_message(message))
        elif callback_query:
            task = asyncio.create_task(process_callback(callback_query))
        else:
            return
        active_tasks.add(task)
        task.add_done_callback(active_tasks.discard)

    if serve_mode == "webhook":
        if not webhook_url:
            raise ValueError("webhook 模式缺少 BOT_WEBHOOK_URL 或 --webhook-url")
        parsed = urlparse(webhook_url)
        full_webhook_url = webhook_url
        if not parsed.path or parsed.path == "/":
            full_webhook_url = webhook_url.rstrip("/") + webhook_path
        else:
            webhook_path = parsed.path
        await client.call(
            "setWebhook",
            {
                "url": full_webhook_url,
                **({"secret_token": webhook_secret} if webhook_secret else {}),
                "allowed_updates": ["message", "callback_query"],
            },
        )

        app = web.Application()

        async def webhook_handler(request: web.Request) -> web.Response:
            try:
                if webhook_secret:
                    got = request.headers.get("X-Telegram-Bot-Api-Secret-Token", "")
                    if got != webhook_secret:
                        return web.json_response({"ok": False, "error": "forbidden"}, status=403)
                update = await request.json()
                if isinstance(update, dict):
                    await process_update(update, from_polling=False)
                return web.json_response({"ok": True})
            except Exception:
                return web.json_response({"ok": False}, status=400)

        app.router.add_post(webhook_path, webhook_handler)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, host=webhook_host, port=webhook_port)
        await site.start()
        console.print(
            f"Webhook 已启动: {webhook_host}:{webhook_port}{webhook_path} -> {full_webhook_url}",
            style="green",
        )
        while True:
            await asyncio.sleep(3600)
    else:
        try:
            await client.call("deleteWebhook", {"drop_pending_updates": False})
        except TelegramAPIError:
            pass
        while True:
            try:
                updates = await client.call(
                    "getUpdates",
                    {
                        "offset": offset,
                        "timeout": args.poll_timeout,
                        "allowed_updates": ["message", "callback_query"],
                    },
                )
            except TelegramAPIError as exc:
                console.print(f"轮询错误: {exc}", style="red")
                if (not network_hint_shown) and ("Cannot connect to host" in str(exc)):
                    console.print(
                        "网络提示: 可在 .env 配置 BOT_PROXY=http://127.0.0.1:7890，或设置 BOT_FORCE_IPV4=1 后重启。",
                        style="yellow",
                    )
                    network_hint_shown = True
                if (not conflict_hint_shown) and ("Conflict: terminated by other getUpdates request" in str(exc)):
                    console.print(
                        "冲突提示: 同一 BOT_TOKEN 只能有一个轮询实例。请先关闭其它机器人进程或面板实例后再启动。",
                        style="yellow",
                    )
                    conflict_hint_shown = True
                await asyncio.sleep(2)
                continue

            for update in updates:
                if isinstance(update, dict):
                    await process_update(update, from_polling=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Telegram 表情包工作室：支持克隆/制作表情包并运行机器人服务。"
    )
    sub = parser.add_subparsers(dest="command", required=False)

    sub.add_parser("whoami", help="查看最近与机器人互动的用户")

    clone = sub.add_parser("clone", help="克隆现有表情包")
    source_group = clone.add_mutually_exclusive_group(required=True)
    source_group.add_argument("--source", help="来源短名或链接 (t.me/addstickers/...)")
    source_group.add_argument("--source-name", help="来源表情包短名")
    clone.add_argument("--new-short-name", default=None, help="目标短名（不填则自动生成）")
    clone.add_argument("--new-title", default=None, help="目标标题（不填则自动生成）")
    clone.add_argument(
        "--owner-user-id",
        default=None,
        type=int,
        help="所属 Telegram 用户ID（不填则自动识别最近用户）",
    )
    clone.add_argument("--watermark", default=None, help="静态贴纸署名文本")
    clone.add_argument(
        "--watermark-pos",
        default="br",
        choices=["tl", "tr", "bl", "br", "c"],
        help="署名位置",
    )
    clone.add_argument("--watermark-opacity", default=145, type=int, help="0-255")
    clone.add_argument(
        "--mode",
        default="maker",
        choices=sorted(VISUAL_MODES),
        help="静态贴纸视觉处理模式",
    )
    clone.add_argument(
        "--fit-mode",
        default="contain",
        choices=sorted(FIT_MODES),
        help="静态贴纸图片适配模式",
    )
    clone.add_argument(
        "--clone-mode",
        default="studio",
        choices=sorted(CLONE_MODES),
        help="copy=尽量原样复制静态贴纸，studio=总是重渲染静态贴纸",
    )

    create = sub.add_parser("create", help="用本地素材创建新表情包")
    create.add_argument("--assets-dir", required=True, help="图片素材目录")
    create.add_argument("--new-short-name", required=True, help="目标短名")
    create.add_argument("--new-title", required=True, help="目标表情包标题")
    create.add_argument(
        "--owner-user-id",
        default=None,
        type=int,
        help="所属 Telegram 用户ID（不填则自动识别最近用户）",
    )
    create.add_argument("--default-emoji", default="😀", help="映射缺失时的默认 emoji")
    create.add_argument("--emoji-map", default=None, help="包含 filename,emoji 的 CSV 文件")
    create.add_argument("--watermark", default=None, help="可选署名文本")
    create.add_argument(
        "--watermark-pos",
        default="br",
        choices=["tl", "tr", "bl", "br", "c"],
        help="署名位置",
    )
    create.add_argument("--watermark-opacity", default=145, type=int, help="0-255")
    create.add_argument(
        "--mode",
        default="maker",
        choices=sorted(VISUAL_MODES),
        help="生成贴纸的视觉模式",
    )
    create.add_argument(
        "--fit-mode",
        default="contain",
        choices=sorted(FIT_MODES),
        help="生成贴纸的适配模式",
    )

    serve = sub.add_parser("serve", help="以 Telegram 机器人服务模式运行")
    serve.add_argument("--poll-timeout", default=40, type=int, help="长轮询超时秒数")
    serve.add_argument("--max-jobs", default=3, type=int, help="最大并发克隆任务数")
    serve.add_argument("--progress-step", default=5, type=int, help="进度更新间隔")
    serve.add_argument("--serve-mode", default=None, choices=["poll", "webhook"], help="运行模式：poll 或 webhook")
    serve.add_argument("--webhook-url", default=None, help="公网 https webhook 地址")
    serve.add_argument("--webhook-path", default=None, help="本地服务 webhook 路径")
    serve.add_argument("--webhook-host", default=None, help="webhook 本地绑定 host")
    serve.add_argument("--webhook-port", default=None, type=int, help="webhook 本地绑定端口")
    serve.add_argument("--webhook-secret", default=None, help="webhook 密钥 token")

    return parser


async def async_main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    load_dotenv()
    token = os.getenv("BOT_TOKEN", "").strip()
    api_base = os.getenv("BOT_API_BASE", "").strip() or None
    file_base = os.getenv("BOT_FILE_BASE", "").strip() or None
    proxy = os.getenv("BOT_PROXY", "").strip() or None
    trust_env = os.getenv("BOT_TRUST_ENV", "1").strip().lower() not in {"0", "false", "no", "off"}
    force_ipv4 = os.getenv("BOT_FORCE_IPV4", "0").strip().lower() in {"1", "true", "yes", "on"}
    allow_risky_token = os.getenv("BOT_ALLOW_RISKY_TOKEN", "0").strip().lower() in {"1", "true", "yes", "on"}
    token_ok, token_msg = validate_bot_token(token)
    if (not token_ok) and (not allow_risky_token):
        console.print(f"安全拦截: {token_msg}", style="red")
        console.print("请去 BotFather 重新生成 Token，并更新 .env 后重试。", style="yellow")
        console.print("如需临时绕过校验，可设置 BOT_ALLOW_RISKY_TOKEN=1（不推荐）。", style="yellow")
        return 1
    if (not token_ok) and allow_risky_token:
        console.print(f"安全警告: {token_msg}", style="yellow")
        console.print("已按 BOT_ALLOW_RISKY_TOKEN=1 继续启动，请尽快更换 Token。", style="yellow")

    try:
        async with TelegramBotClient(
            token,
            api_base=api_base,
            file_base=file_base,
            proxy=proxy,
            trust_env=trust_env,
            force_ipv4=force_ipv4,
        ) as client:
            if args.command is None:
                await cmd_wizard(client)
            elif args.command == "whoami":
                await cmd_whoami(client)
            elif args.command == "clone":
                await cmd_clone(client, args)
            elif args.command == "create":
                await cmd_create(client, args)
            elif args.command == "serve":
                await cmd_serve(client, args)
            else:
                raise ValueError(f"未知命令: {args.command}")
    except (TelegramAPIError, ValueError) as exc:
        console.print(f"错误: {exc}", style="red")
        return 2

    return 0


def main() -> None:
    raise SystemExit(asyncio.run(async_main()))


if __name__ == "__main__":
    main()


