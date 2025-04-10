import httpx
import asyncio
from typing import List, Optional, Dict, Any
from urllib.parse import quote
import math
import re
import time
import os

from astrbot.api.event import filter, AstrMessageEvent, MessageEventResult
from astrbot.api.star import Context, Star, register
from astrbot.api.message_components import Plain, Image, At
from astrbot.core.config import AstrBotConfig
import logging
from logging import FileHandler, Formatter

# --- Logging Setup ---
log_dir = os.path.dirname(__file__)
log_file_path = os.path.join(log_dir, 'log.txt')

try:
    from astrbot.core.utils.logger import logger
    logger = logger.bind(plugin="AlistPlugin")
    log_formatter = Formatter('%(asctime)s - %(name)s - %(levelname)s - %(plugin)s - %(message)s')
    file_handler = FileHandler(log_file_path, encoding='utf-8')
    file_handler.setFormatter(log_formatter)
    file_handler.setLevel(logging.DEBUG)
    logger.setLevel(logging.DEBUG)
    if not any(isinstance(h, FileHandler) and getattr(h, 'baseFilename', None) == log_file_path for h in logger.handlers):
        logger.addHandler(file_handler)
        logger.info(f"File logging configured for AstrBot logger at: {log_file_path}")
except ImportError:
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)
    log_formatter = Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler = FileHandler(log_file_path, encoding='utf-8')
    file_handler.setFormatter(log_formatter)
    file_handler.setLevel(logging.DEBUG)
    if not any(isinstance(h, FileHandler) and getattr(h, 'baseFilename', None) == log_file_path for h in logger.handlers):
        logger.addHandler(file_handler)
        logger.info(f"File logging configured for standard logger at: {log_file_path}")
    if not logging.getLogger().hasHandlers():
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    logger.info("AstrBot logger not found, using standard logging for AlistPlugin.")

# --- Alist API Client ---
class AlistClient:
    def __init__(self, host: str, token: str, timeout: int = 10):
        self.host = host.rstrip('/')
        self.token = token
        self.timeout = timeout
        self.headers = {
            "Authorization": self.token,
            "Content-Type": "application/json",
            "User-Agent": "AstrBot/AlistPlugin"
        }
        self._client: Optional[httpx.AsyncClient] = None

    async def get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            logger.debug("Creating new httpx.AsyncClient instance.")
            self._client = httpx.AsyncClient(
                base_url=self.host,
                headers=self.headers,
                timeout=self.timeout,
                follow_redirects=True
            )
        return self._client

    async def close(self):
        if self._client and not self._client.is_closed:
            logger.debug("Closing httpx.AsyncClient instance.")
            await self._client.aclose()
        self._client = None

    async def _request(self, method: str, path: str, **kwargs) -> Optional[Any]:
        client = await self.get_client()
        url = f"/api{path}"
        try:
            logger.debug(f"Alist API Request: {method} {url} kwargs={kwargs}")
            response = await client.request(method, url, **kwargs)
            logger.debug(f"Alist API Response Status: {response.status_code}")
            response.raise_for_status()
            data = response.json()
            logger.debug(f"Alist API Response Data (type: {type(data)}): {data}")
            if isinstance(data, dict) and "code" in data:
                if data.get("code") == 200:
                    if path == "/fs/list":
                        return data.get("data")
                    else:
                         return data.get("data") if "data" in data else data
                else:
                    logger.error(f"Alist API error ({path}): Code {data.get('code')} - {data.get('message', 'Unknown error')}. Response: {data}")
                    return None
            elif isinstance(data, list) and response.status_code == 200:
                 logger.debug(f"Alist API ({path}) returned a list directly, assuming success.")
                 return {"content": data, "total": len(data)}
            elif response.status_code == 200:
                 logger.warning(f"Alist API ({path}) returned an unexpected successful response format: {data}")
                 return data
            else:
                 logger.error(f"Alist API returned unexpected status {response.status_code} with data: {data}")
                 return None
        except httpx.HTTPStatusError as e:
            logger.error(f"Alist API HTTP Status Error ({path}): {e.response.status_code}. Response: {e.response.text}")
            if e.response.status_code == 500:
                 try:
                     error_data = e.response.json()
                     if "storage not found" in error_data.get("message", "") or "object not found" in error_data.get("message", ""):
                         logger.error(f"Path/Storage not found for: {path}. Message: {error_data.get('message')}")
                 except Exception:
                     pass
            return None
        except httpx.RequestError as e:
            logger.error(f"Alist API Request Error ({path}): {type(e).__name__} - {e}")
            return None
        except Exception as e:
            logger.error(f"Alist API unexpected error ({path}): {e}", exc_info=True)
            return None

    async def _simple_request(self, method: str, path: str, **kwargs) -> Optional[httpx.Response]:
         client = await self.get_client()
         url = f"/api{path}"
         try:
             logger.debug(f"Simple API Request: {method} {url} kwargs={kwargs}")
             response = await client.request(method, url, **kwargs)
             logger.debug(f"Simple API Response Status: {response.status_code}")
             return response
         except httpx.RequestError as e:
             logger.error(f"Simple API Request Error ({path}): {type(e).__name__} - {e}")
             return None
         except Exception as e:
             logger.error(f"Simple API unexpected error ({path}): {e}", exc_info=True)
             return None

    async def search(self, keywords: str, page: int = 1, per_page: int = 100, parent: str = "/") -> Optional[Dict[str, Any]]:
        """Search for files using /api/fs/search with pagination."""
        payload = {
            "parent": parent,
            "keywords": keywords,
            "page": page,
            "per_page": max(1, per_page)  # Ensure per_page is at least 1
        }
        logger.debug(f"Calling /api/fs/search with payload: {payload}")
        result = await self._request("POST", "/fs/search", json=payload)
        return result if isinstance(result, dict) else None

    async def list_directory(self, path: str) -> Optional[Dict[str, Any]]:
        """List contents of a directory using /api/fs/list with per_page=0."""
        payload = {
            "path": path,
            "password": "",
            "page": 1,
            "per_page": 0,
            "refresh": False
        }
        logger.debug(f"Calling /api/fs/list with per_page=0 and raw path: {path}")
        result = await self._request("POST", "/fs/list", json=payload)
        return result if isinstance(result, dict) else None

    async def storage_list(self) -> Optional[List[Dict[str, Any]]]:
        result_data = await self._request("GET", "/admin/storage/list")
        if isinstance(result_data, dict) and 'content' in result_data and isinstance(result_data['content'], list):
            logger.debug(f"Extracted storage list from result_data['content']. Total items: {result_data.get('total', 'N/A')}")
            return result_data['content']
        else:
            if isinstance(result_data, list):
                 logger.warning("storage_list API returned a list directly. Processing as list.")
                 return result_data
            logger.error(f"Unexpected data structure received from _request for storage_list: {type(result_data)}. Expected dict with 'content' list or a direct list.")
            return None

    async def storage_enable(self, storage_id: int) -> tuple[bool, str]:
        response = await self._simple_request("POST", f"/admin/storage/enable?id={storage_id}")
        if response is None:
            return False, "请求 Alist API 失败 (连接错误?)"
        try:
            data = response.json()
            message = data.get("message", f"HTTP {response.status_code}")
            if response.status_code == 200 and data.get("code") == 200:
                return True, message
            else:
                logger.error(f"storage_enable failed: Status {response.status_code}, Body {data}")
                return False, message
        except Exception as e:
            logger.error(f"Error parsing storage_enable response: {e}", exc_info=True)
            return False, f"解析响应失败: {response.text}"

    async def storage_disable(self, storage_id: int) -> tuple[bool, str]:
        response = await self._simple_request("POST", f"/admin/storage/disable?id={storage_id}")
        if response is None:
            return False, "请求 Alist API 失败 (连接错误?)"
        try:
            data = response.json()
            message = data.get("message", f"HTTP {response.status_code}")
            if response.status_code == 200 and data.get("code") == 200:
                return True, message
            else:
                logger.error(f"storage_disable failed: Status {response.status_code}, Body {data}")
                return False, message
        except Exception as e:
            logger.error(f"Error parsing storage_disable response: {e}", exc_info=True)
            return False, f"解析响应失败: {response.text}"

    async def storage_delete(self, storage_id: int) -> bool:
        payload = [storage_id]
        response = await self._simple_request("POST", "/admin/storage/delete", json=payload)
        if response is None:
             logger.error("storage_delete failed: No response from API.")
             return False
        try:
            data = response.json()
            if response.status_code == 200 and data.get("code") == 200:
                logger.info(f"Successfully deleted storage ID: {storage_id}")
                return True
            else:
                logger.error(f"storage_delete failed: Status {response.status_code}, Body {data}")
                return False
        except Exception as e:
            logger.error(f"Error parsing storage_delete response: {e}", exc_info=True)
            return False

# --- AstrBot Plugin ---
@register(
    "astrbot_plugin_alist",
    "Cline (Generated)",
    "通过机器人查看alist，支持管理存储和搜索文件",
    "1.1.4514",  # Incremented version
    ""
)
class AlistPlugin(Star):
    def __init__(self, context: Context, config: AstrBotConfig):
        logger.debug("AlistPlugin __init__ called.")
        super().__init__(context)
        self.config = config
        self.alist_client: Optional[AlistClient] = None
        self.lock = asyncio.Lock()
        self.last_search_state: Dict[str, Any] = {}
        self.search_state_timeout: int = 180

        logger.debug("Creating task for _initialize_client")
        task_creator = getattr(context, 'create_task', asyncio.create_task)
        task_creator(self._initialize_client())
        logger.info("Alist Plugin loaded (init called).")

    async def _initialize_client(self):
        logger.debug("Attempting to initialize Alist client asynchronously...")
        async with self.lock:
            if self.alist_client:
                logger.debug("Closing existing Alist client before async re-initialization.")
                try:
                    await self.alist_client.close()
                except Exception as e:
                    logger.error(f"Exception closing existing client: {e}", exc_info=True)
                self.alist_client = None

            host = self.config.get("alist_host")
            token = self.config.get("alist_token")
            timeout = self.config.get("timeout", 10)

            masked_token = f"{token[:5]}..." if token and len(token) > 5 else token
            logger.debug(f"Read config for async init - host: {host}, token: {masked_token}, timeout: {timeout}")

            if not host or not token:
                logger.error("Alist host or token is missing or empty in plugin settings (async init).")
                self.alist_client = None
                return

            try:
                self.alist_client = AlistClient(host=host, token=token, timeout=timeout)
                logger.info(f"Alist client initialized asynchronously for host: {host}")
            except Exception as e:
                logger.error(f"Failed to create AlistClient object in async init: {e}", exc_info=True)
                self.alist_client = None

        logger.debug(f"Async initialization finished. Client is {'set' if self.alist_client else 'None'}.")

    async def _get_client(self) -> Optional[AlistClient]:
        logger.debug(f"Entering _get_client. Current client state: {'Initialized' if self.alist_client else 'None'}")
        if self.alist_client is None:
             logger.debug("Client is None in _get_client, waiting on lock for potential initialization.")
             async with self.lock:
                 if self.alist_client is None:
                     await self._initialize_client()
                     if self.alist_client is None:
                         logger.error("Client is still None after acquiring lock and re-attempting init.")
                 else:
                      logger.debug("Client was initialized while waiting for lock.")

        if self.alist_client is None:
             logger.error("Alist client is still None after _get_client call.")
        return self.alist_client

    def _format_size(self, size_bytes: int) -> str:
        if size_bytes < 0: return "未知大小"
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024**2:
            return f"{size_bytes/1024:.1f} KB"
        elif size_bytes < 1024**3:
            return f"{size_bytes/1024**2:.1f} MB"
        elif size_bytes < 1024**4:
            return f"{size_bytes/1024**3:.1f} GB"
        else:
            return f"{size_bytes/1024**4:.1f} TB"

    async def terminate(self):
        logger.info("Alist Plugin terminating...")
        if self.alist_client:
            logger.debug("Closing Alist client during terminate.")
            try:
                await self.alist_client.close()
            except Exception as e:
                 logger.error(f"Error closing Alist client during terminate: {e}", exc_info=True)
        logger.info("Alist Plugin terminated.")

    async def _execute_api_call_and_format(self, event: AstrMessageEvent, client: AlistClient, page: int, per_page: int, parent: str = "/", keywords: Optional[str] = None) -> Optional[str]:
        is_search = keywords is not None
        api_call_type = "search" if is_search else "list"
        api_keywords = keywords if is_search else ""

        logger.debug(f"Executing API helper - Type: {api_call_type}, API Keywords: '{api_keywords}', Page: {page}, PerPage: {per_page}, Parent: {parent}")

        full_content = []
        total = 0
        api_data = None

        try:
            if is_search:
                # For search, fetch the specific page from the API
                api_data = await client.search(keywords=api_keywords, page=page, per_page=per_page, parent=parent)
                if api_data:
                    full_content = api_data.get("content", [])
                    total = api_data.get("total", 0)
            else:
                # For directory listing, fetch all results and paginate client-side
                api_data = await client.list_directory(path=parent)
                if api_data:
                    full_content = api_data.get("content", [])
                    total = len(full_content)
                    logger.debug(f"List directory successful. Total items fetched: {total}")

            if api_data is None:
                action_desc = f"搜索 '{api_keywords}'" if is_search else "列出目录"
                return f"❌ 在路径 '{parent}' 中{action_desc}时出错或未找到结果。"

            total_pages = math.ceil(total / per_page) if per_page > 0 else 1

            if is_search:
                # For search, use the API-provided content directly (already paginated)
                display_content = full_content
            else:
                # For listing, paginate client-side
                start_index = (page - 1) * per_page
                end_index = start_index + per_page
                display_content = full_content[start_index:end_index] if per_page > 0 else full_content

            if not display_content:
                 action_desc = f"与 '{api_keywords}' 相关的文件" if is_search else "任何文件或文件夹"
                 if page == 1:
                     if total == 0:
                         return f"❎ 在路径 '{parent}' 中未能找到{action_desc}。"
                     else:
                         return f"❎ 在路径 '{parent}' 中找到 {total} 个结果，但无法显示第 1 页。"
                 else:
                     return f"❎ 在路径 '{parent}' 的第 {page} 页没有找到{action_desc} (共 {total_pages} 页)。"

            reply_text = f"✅ 在 '{parent}' 中找到 {total} 个结果 (第 {page}/{total_pages} 页):\n"

            # Calculate overall index for display
            start_index = (page - 1) * per_page if is_search else (page - 1) * per_page
            for i, item in enumerate(display_content):
                overall_index = start_index + i + 1
                is_dir = item.get("is_dir", False)
                item_type = "📁" if is_dir else "📄"
                size_str = self._format_size(item.get("size", 0)) if not is_dir else ""
                name = item.get('name', '未知名称')
                reply_text += f"\n{overall_index}. {item_type} {name} {'('+size_str+')' if size_str else ''}"
                if not is_dir and client.host:
                    try:
                        item_parent_path = item.get("parent", "/")
                        full_path = os.path.join(item_parent_path, name).replace("\\", "/")
                        if not full_path.startswith("/"):
                            full_path = "/" + full_path
                        encoded_path = quote(full_path)
                        link = f"{client.host}/d{encoded_path}"
                        reply_text += f"\n  Link: {link}"
                    except Exception as link_e:
                        logger.error(f"Error generating link for {name}: {link_e}")

            if total_pages > 1:
                reply_text += f"\n\n📄 使用 /al np 翻页 (下一页), /al lp 翻页 (上一页)。 (共 {total_pages} 页)"
            if any(item.get("is_dir") for item in display_content):
                reply_text += "\n\n➡️ 使用 /al fl <序号> 进入文件夹。"

            sender_id = event.get_sender_id()
            if sender_id:
                 self.last_search_state[sender_id] = {
                     "keywords": keywords,
                     "results": full_content,  # Store current page for search, full content for list
                     "parent": parent,
                     "current_page": page,
                     "total_pages": total_pages,
                     "timestamp": time.time(),
                     "total": total  # Store total for pagination calculations
                 }
                 logger.debug(f"Stored state for user {sender_id}: page {page}/{total_pages}, keywords '{keywords}', parent '{parent}', total {total} items")
            else:
                 logger.warning("Could not get sender ID from event, state not stored.")

            return reply_text

        except Exception as e:
            logger.error(f"Error during API call execution/formatting: {e}", exc_info=True)
            return f"处理请求时发生内部错误，请查看日志。"

    @filter.command("al s", alias={'alist s', 'al 搜索', 'alist 搜索', 's', '搜索'})
    async def search_command(self, event: AstrMessageEvent, keywords: str):
        """使用 /al s 命令在 Alist 中搜索文件。用法: /al s <关键词>"""
        logger.debug(f"search_command (now /al s) called with keywords: '{keywords}'")
        page = 1
        parent = "/"

        client = await self._get_client()
        if not client:
            yield event.plain_result("错误：Alist 客户端未配置或初始化失败。")
            return

        per_page = self.config.get("search_result_limit", 10)
        yield event.plain_result(f"⏳ 正在根目录 '/' 搜索 '{keywords}'...")

        result_message = await self._execute_api_call_and_format(event, client, page, per_page, parent, keywords=keywords)
        yield event.plain_result(result_message)

    @filter.command("al fl", alias={'alist fl', 'al folder', 'alist folder', 'al 进入', 'alist 进入', 'fl', 'folder', '进入'})
    async def folder_command(self, event: AstrMessageEvent, index_str: str):
        """进入指定序号的文件夹。用法: /al fl <序号>"""
        logger.debug(f"folder_command (now /al fl) called with index string: {index_str}")

        sender_id = event.get_sender_id()
        if not sender_id:
            yield event.plain_result("❌ 无法获取用户信息。")
            return

        state = self.last_search_state.get(sender_id)
        if not state or (time.time() - state["timestamp"]) > self.search_state_timeout:
            yield event.plain_result("❌ 没有找到最近的搜索记录或已超时 (3分钟)。请重新使用 /al s 搜索。")
            return

        try:
            index = int(index_str)
            if not (0 < index <= state.get("total", len(state["results"]))):
                 yield event.plain_result(f"❌ 无效的序号 '{index}'。请从 1 到 {state.get('total', len(state['results']))} 中选择。")
                 return

            # Adjust index for the current page's results
            page_start_index = (state["current_page"] - 1) * self.config.get("search_result_limit", 10) + 1
            relative_index = index - page_start_index
            if not (0 <= relative_index < len(state["results"])):
                yield event.plain_result(f"❌ 序号 {index} 不在当前页 (第 {state['current_page']} 页) 的范围内。")
                return

            selected_item = state["results"][relative_index]
            if not selected_item.get("is_dir"):
                 yield event.plain_result(f"❌ 无法进入，序号 {index} ('{selected_item.get('name')}') 不是文件夹。")
                 return

            folder_name = selected_item.get("name")
            if "parent" in selected_item and selected_item["parent"]:
                parent_path = selected_item["parent"]
            else:
                parent_path = state.get("parent", "/")

            if parent_path == "/":
                new_parent = f"/{folder_name}"
            else:
                new_parent = f"{parent_path.rstrip('/')}/{folder_name}"

            if not new_parent.startswith("/") and new_parent != "/":
                new_parent = "/" + new_parent
            new_parent = new_parent.replace("//", "/")

            logger.debug(f"Entering folder: {new_parent}")

            client = await self._get_client()
            if not client:
                yield event.plain_result("❌ 错误：Alist 客户端未配置或初始化失败。")
                return

            per_page = self.config.get("search_result_limit", 10)
            yield event.plain_result(f"⏳ 正在进入并列出 '{new_parent}'...")

            result_message = await self._execute_api_call_and_format(
                event, client, page=1, per_page=per_page, parent=new_parent, keywords=None
            )
            yield event.plain_result(result_message)

        except ValueError:
            yield event.plain_result(f"❌ 无效的序号 '{index_str}'。请输入一个数字。")
        except IndexError:
             logger.error(f"IndexError accessing state['results'] with index {index-1}. State: {state}")
             yield event.plain_result(f"❌ 内部错误：无法在缓存的结果中找到序号 {index}。请重试。")
        except Exception as e:
            logger.error(f"Error during folder navigation: {e}", exc_info=True)
            yield event.plain_result(f"进入文件夹时发生内部错误，请查看日志。")

    @filter.command("al home", alias={'alist home'})
    async def list_home_command(self, event: AstrMessageEvent):
        """列出 Alist 根目录的内容。用法: /al home"""
        logger.debug("list_home_command called.")
        page = 1
        parent = "/"

        client = await self._get_client()
        if not client:
            yield event.plain_result("错误：Alist 客户端未配置或初始化失败。")
            return

        per_page = self.config.get("search_result_limit", 10)
        yield event.plain_result(f"⏳ 正在列出根目录 '/' 的内容...")

        result_message = await self._execute_api_call_and_format(event, client, page, per_page, parent, keywords=None)
        yield event.plain_result(result_message)

    @filter.command("al np", alias={'alist np', 'al 下一页', 'alist 下一页', 'np', '下一页'})
    async def next_page_command(self, event: AstrMessageEvent):
        """跳转到搜索列表结果的下一页。"""
        sender_id = event.get_sender_id()
        if not sender_id:
             yield event.plain_result("❌ 无法获取用户信息。")
             return

        logger.debug(f"next_page_command (now /al np) called by user {sender_id}")
        state = self.last_search_state.get(sender_id)
        if not state or (time.time() - state["timestamp"]) > self.search_state_timeout:
            yield event.plain_result("❌ 没有找到最近的记录或已超时 (3分钟)。请重新使用 /al s 或 /al fl。")
            return

        if state["current_page"] >= state["total_pages"]:
            yield event.plain_result(f"❌ 已经是最后一页了 (第 {state['current_page']}/{state['total_pages']} 页)。")
            return

        next_page = state["current_page"] + 1
        keywords = state["keywords"]
        parent = state["parent"]
        logger.debug(f"Fetching next page ({next_page}) for parent '{parent}' for user {sender_id}")

        client = await self._get_client()
        if not client:
            yield event.plain_result("错误：Alist 客户端未配置或初始化失败。")
            return

        per_page = self.config.get("search_result_limit", 10)
        yield event.plain_result(f"⏳ 正在获取下一页 (第 {next_page} 页)...")

        result_message = await self._execute_api_call_and_format(event, client, next_page, per_page, parent, keywords=keywords)
        yield event.plain_result(result_message)

    @filter.command("al lp", alias={'alist lp', 'al 上一页', 'alist 上一页', 'lp', '上一页'})
    async def last_page_command(self, event: AstrMessageEvent):
        """跳转到搜索列表结果的上一页。"""
        sender_id = event.get_sender_id()
        if not sender_id:
             yield event.plain_result("❌ 无法获取用户信息。")
             return

        logger.debug(f"last_page_command (now /al lp) called by user {sender_id}")
        state = self.last_search_state.get(sender_id)
        if not state or (time.time() - state["timestamp"]) > self.search_state_timeout:
            yield event.plain_result("❌ 没有找到最近的记录或已超时 (3分钟)。请重新使用 /al s 或 /al fl。")
            return

        if state["current_page"] <= 1:
            yield event.plain_result(f"❌ 已经是第一页了。")
            return

        prev_page = state["current_page"] - 1
        keywords = state["keywords"]
        parent = state["parent"]
        logger.debug(f"Fetching previous page ({prev_page}) for parent '{parent}' for user {sender_id}")

        client = await self._get_client()
        if not client:
            yield event.plain_result("错误：Alist 客户端未配置或初始化失败。")
            return

        per_page = self.config.get("search_result_limit", 10)
        yield event.plain_result(f"⏳ 正在获取上一页 (第 {prev_page} 页)...")

        result_message = await self._execute_api_call_and_format(event, client, prev_page, per_page, parent, keywords=keywords)
        yield event.plain_result(result_message)

    @filter.command("al list", alias={'alist list', 'al 列表', 'alist 列表', 'list', '列表'})
    async def list_storages(self, event: AstrMessageEvent):
        """列出所有 Alist 存储。用法: /al list"""
        logger.debug("list_storages (now /al list) command called.")
        
        client = await self._get_client()
        if not client:
            yield event.plain_result("错误：Alist 客户端未配置或初始化失败。")
            return

        yield event.plain_result("⏳ 正在获取存储列表...")

        try:
            storages = await client.storage_list()
        
            if storages is None:
                yield event.plain_result("❌ 获取存储列表失败，请检查 Alist 连接和日志。")
                return

            if not isinstance(storages, list):
                logger.error(f"Unexpected response type for storage_list: {type(storages)}. Expected list.")
                yield event.plain_result("❌ 获取存储列表时收到意外的响应格式。")
                return

            if not storages:
                yield event.plain_result("❎ Alist 中没有配置任何存储。")
                return

            reply_text = "🗄️ Alist 存储列表:\n"
            for storage in storages:
                mount_path = storage.get('mount_path', '未知路径')
                driver = storage.get('driver', '未知驱动')
                status = storage.get('status', '未知状态')
                storage_id = storage.get('id', '??')
                enabled_icon = "✅" if status == 'work' else "❌"
                reply_text += f"\n{enabled_icon} ID: {storage_id} | Path: {mount_path} ({driver}) - {status}"

            yield event.plain_result(reply_text)

        except Exception as e:
            logger.error(f"Error listing storages: {e}", exc_info=True)
            yield event.plain_result(f"获取存储列表时发生内部错误，请查看日志。")

    @filter.command("al enable", alias={'alist enable', 'al 启用', 'alist 启用', 'enable', '启用'})
    async def enable_storage(self, event: AstrMessageEvent, storage_id: int):
        """启用指定的 Alist 存储。用法: /al enable <存储ID>"""
        logger.debug(f"enable_storage (now /al enable) command called for ID: {storage_id}")
        
        client = await self._get_client()
        if not client:
            yield event.plain_result("错误：Alist 客户端未配置或初始化失败。")
            return

        yield event.plain_result(f"⏳ 正在尝试启用存储 ID: {storage_id}...")
        try:
            success, message = await client.storage_enable(storage_id)
            if success:
                yield event.plain_result(f"✅ 成功启用存储 ID: {storage_id} ({message})")
            else:
                yield event.plain_result(f"❌ 启用存储 ID: {storage_id} 失败: {message}")
        except Exception as e:
            logger.error(f"Error enabling storage {storage_id}: {e}", exc_info=True)
            yield event.plain_result(f"启用存储时发生内部错误，请查看日志。")

    @filter.command("al disable", alias={'alist disable', 'al 禁用', 'alist 禁用', 'disable', '禁用'})
    async def disable_storage(self, event: AstrMessageEvent, storage_id: int):
        """禁用指定的 Alist 存储。用法: /al disable <存储ID>"""
        logger.debug(f"disable_storage (now /al disable) command called for ID: {storage_id}")
        
        client = await self._get_client()
        if not client:
            yield event.plain_result("错误：Alist 客户端未配置或初始化失败。")
            return

        yield event.plain_result(f"⏳ 正在尝试禁用存储 ID: {storage_id}...")
        try:
            success, message = await client.storage_disable(storage_id)
            if success:
                yield event.plain_result(f"✅ 成功禁用存储 ID: {storage_id} ({message})")
            else:
                yield event.plain_result(f"❌ 禁用存储 ID: {storage_id} 失败: {message}")
        except Exception as e:
            logger.error(f"Error disabling storage {storage_id}: {e}", exc_info=True)
            yield event.plain_result(f"禁用存储时发生内部错误，请查看日志。")

    @filter.command("al delete", alias={'alist delete', 'al 删除', 'alist 删除', 'delete', '删除'})
    async def delete_storage(self, event: AstrMessageEvent, storage_id: int):
        """删除指定的 Alist 存储。用法: /al delete <存储ID>"""
        logger.debug(f"delete_storage (now /al delete) command called for ID: {storage_id}")
        
        client = await self._get_client()
        if not client:
            yield event.plain_result("错误：Alist 客户端未配置或初始化失败。")
            return

        yield event.plain_result(f"⏳ 正在尝试删除存储 ID: {storage_id}...")
        try:
            success = await client.storage_delete(storage_id)
            if success:
                yield event.plain_result(f"✅ 成功删除存储 ID: {storage_id}")
            else:
                yield event.plain_result(f"❌ 删除存储 ID: {storage_id} 失败。请检查 Alist 连接和日志。")
        except Exception as e:
            logger.error(f"Error deleting storage {storage_id}: {e}", exc_info=True)
            yield event.plain_result(f"删除存储时发生内部错误，请查看日志。")

    @filter.command("al help", alias={'alist help', 'al 帮助', 'alist 帮助', 'help', '帮助'})
    async def help_command(self, event: AstrMessageEvent):
        """显示 Alist 插件的所有命令及其用法。"""
        reply_text = "首次使用记得填写alist的地址和token\n"
        reply_text += "Alist 插件命令 (前缀 /al 或 /alist):\n"
        reply_text += "/al s <关键词> - 在 Alist 中搜索文件。\n"
        reply_text += "/al fl <序号> - 进入指定序号的文件夹。\n"
        reply_text += "/al home - 列出根目录内容。\n"
        reply_text += "/al np - 跳转到列表结果的下一页。\n"
        reply_text += "/al lp - 跳转到列表结果的上一页。\n"
        reply_text += "/al list - 列出所有 Alist 存储。\n"
        reply_text += "/al enable <存储ID> - 启用指定的 Alist 存储。\n"
        reply_text += "/al disable <存储ID> - 禁用指定的 Alist 存储。\n"
        reply_text += "/al delete <存储ID> - 删除指定的 Alist 存储 (请谨慎使用)。\n"
        reply_text += "/al help - 显示此帮助信息。\n"
        reply_text += "\n使用示例: /al s asmr, /al fl 1, /al np, /al list, /al enable 1"
        yield event.plain_result(reply_text)
