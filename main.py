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
    def __init__(self, host: str, username: Optional[str] = None, password: Optional[str] = None, token: Optional[str] = None, timeout: int = 10):
        self.host = host.rstrip('/')
        self.username = username
        self.password = password
        self.token = token
        self.timeout = timeout
        self.headers = {
            "Content-Type": "application/json",
            "User-Agent": "AstrBot/AlistPlugin"
        }
        self._client: Optional[httpx.AsyncClient] = None

    async def authenticate(self):
        if not self.username or not self.password:
            logger.error("用户名或密码未配置，无法进行身份验证。")
            return

        login_url = f"{self.host}/api/auth/login"
        credentials = {"username": self.username, "password": self.password}

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                response = await client.post(login_url, json=credentials)
                response.raise_for_status()
                auth_data = response.json()
                self.token = auth_data.get("data", {}).get("token")
                if not self.token:
                    logger.error("未能从 Alist API 响应中获取令牌。")
                    return
                self.headers["Authorization"] = self.token
            except httpx.HTTPStatusError as e:
                logger.error(f"身份验证失败，状态码: {e.response.status_code}, 响应: {e.response.text}")
                return
            except Exception as e:
                logger.error(f"身份验证时发生错误: {e}")
                return
            logger.info("身份验证成功，令牌已设置。")

    async def get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            logger.debug("Creating new httpx.AsyncClient instance.")
            if not self.token:
                await self.authenticate()
            else:
                self.headers["Authorization"] = self.token
            
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
                    # Handle cases where data might be directly under 'data' or the root
                    return data.get("data") if "data" in data else data
                else:
                    logger.error(f"Alist API error ({path}): Code {data.get('code')} - {data.get('message', 'Unknown error')}. Response: {data}")
                    return None
            elif isinstance(data, list) and response.status_code == 200:
                 logger.debug(f"Alist API ({path}) returned a list directly, assuming success.")
                 # Wrap list in a dict consistent with other responses if needed by caller
                 return {"content": data, "total": len(data)} # Or just return data if caller handles lists
            elif response.status_code == 200:
                 logger.warning(f"Alist API ({path}) returned an unexpected successful response format: {data}")
                 return data # Return data as is, let caller handle
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

    async def get_file_info(self, path: str) -> Optional[Dict[str, Any]]:
        payload = {
            "path": path
        }
        logger.debug(f"Calling /api/fs/get with payload: {payload}")
        result = await self._request("POST", "/fs/get", json=payload)
        return result if isinstance(result, dict) else None
    
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
        # Ensure the result is a dict, even if _request returns root data
        return result if isinstance(result, dict) else None

    async def list_directory(self, path: str) -> Optional[Dict[str, Any]]:
        """List contents of a directory using /api/fs/list with per_page=0."""
        payload = {
            "path": path,
            "password": "",
            "page": 1,
            "per_page": 0, # Fetch all items
            "refresh": False
        }
        logger.debug(f"Calling /api/fs/list with per_page=0 and raw path: {path}")
        result = await self._request("POST", "/fs/list", json=payload)
        # Ensure the result is a dict, even if _request returns root data
        return result if isinstance(result, dict) else None

    async def storage_list(self) -> Optional[List[Dict[str, Any]]]:
        result_data = await self._request("GET", "/admin/storage/list")
        # Handle both direct list and nested content structure
        if isinstance(result_data, dict) and 'content' in result_data and isinstance(result_data['content'], list):
            logger.debug(f"Extracted storage list from result_data['content']. Total items: {result_data.get('total', 'N/A')}")
            return result_data['content']
        elif isinstance(result_data, list):
             logger.warning("storage_list API returned a list directly. Processing as list.")
             return result_data
        else:
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
        response = await self._simple_request("POST", f"/admin/storage/delete?id={storage_id}")
        if response is None:
            logger.error("storage_delete failed: No response from API.")
            return False
        try:
            data = response.json()
            logger.debug(f"storage_delete response: Status {response.status_code}, Body {data}")
            if response.status_code == 200 and data.get("code") == 200:
                logger.info(f"Successfully deleted storage ID: {storage_id}")
                return True
            else:
                logger.error(f"storage_delete failed: Status {response.status_code}, Code {data.get('code', 'N/A')}, Message {data.get('message', 'No message')}")
                return False
        except Exception as e:
            logger.error(f"Error parsing storage_delete response: {e}, Response text: {response.text}", exc_info=True)
            return False

    async def get_me(self) -> Optional[Dict[str, Any]]:
        """Get current user information using /api/me."""
        logger.debug("Calling /api/me")
        result = await self._request("GET", "/me")
        # The actual user data might be nested under 'data' or be the root object
        if isinstance(result, dict):
             # Check common nesting patterns
             if "data" in result and isinstance(result["data"], dict):
                 logger.debug(f"/api/me returned nested data: {result['data']}")
                 return result["data"]
             elif "id" in result: # Check if root object looks like user data
                 logger.debug(f"/api/me returned root data: {result}")
                 return result
             else:
                 logger.warning(f"/api/me returned unexpected dict structure: {result}")
                 return None
        else:
            logger.error(f"/api/me did not return a dictionary: {result}")
            return None

# --- AstrBot Plugin ---
@register(
    "astrbot_plugin_alist",
    "Cline (Generated)",
    "通过机器人查看alist，支持管理存储和搜索文件",
    "1.2.1",  # Incremented version for history feature + admin fix
    ""
)
class AlistPlugin(Star):
    def __init__(self, context: Context, config: AstrBotConfig):
        logger.debug("AlistPlugin __init__ called.")
        super().__init__(context)
        self.config = config
        self.alist_client: Optional[AlistClient] = None
        self.lock = asyncio.Lock()
        # Store a list of states for history [oldest, ..., current]
        self.last_search_state: Dict[str, List[Dict[str, Any]]] = {}
        self.search_state_timeout: int = 180 # Timeout for individual states remains
        self.max_history_depth = 10 # Limit how many levels deep we store
        self.user_base_path: str = "/" # Default base path

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
            username = self.config.get("alist_username")
            password = self.config.get("alist_password")
            timeout = self.config.get("timeout", 10)

            masked_token = f"{token[:5]}..." if token and len(token) > 5 else token
            logger.debug(f"Read config for async init - host: {host}, token: {masked_token}, timeout: {timeout}")

            if not host:
                logger.error("Alist host or token is missing or empty in plugin settings (async init).")
                self.alist_client = None
                return

            try:
                if token:
                    self.alist_client = AlistClient(host=host, token=token, timeout=timeout)
                elif username and password:
                    self.alist_client = AlistClient(host=host, username=username, password=password, timeout=timeout)
                    await self.alist_client.authenticate()
                else:
                    logger.error("Alist token 或用户名/密码未配置，无法初始化客户端。")
                    self.alist_client = None
                    return
                
                logger.info(f"Alist client initialized asynchronously for host: {host}")

                # --- Get user base path ---
                try:
                    user_info = await self.alist_client.get_me()
                    if user_info and isinstance(user_info, dict):
                        base_path = user_info.get("base_path", "/")
                        # Normalize the base path
                        if not base_path: base_path = "/"
                        if not base_path.startswith("/"): base_path = "/" + base_path
                        # Keep trailing slash for joining, unless it's just "/"
                        # if base_path != "/" and base_path.endswith("/"): base_path = base_path.rstrip("/")

                        self.user_base_path = base_path
                        logger.info(f"Successfully fetched user info. Base path set to: '{self.user_base_path}'")
                    else:
                        logger.warning(f"Failed to get valid user info from /api/me. Response: {user_info}. Using default base path '/'.")
                        self.user_base_path = "/"
                except Exception as me_e:
                    logger.error(f"Error calling /api/me: {me_e}. Using default base path '/'.", exc_info=True)
                    self.user_base_path = "/"
                # --- End get user base path ---

            except Exception as e:
                logger.error(f"Failed to create AlistClient object in async init: {e}", exc_info=True)
                self.alist_client = None
                self.user_base_path = "/" # Reset on client creation failure

        logger.debug(f"Async initialization finished. Client is {'set' if self.alist_client else 'None'}. Base path: '{self.user_base_path}'")

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
        # 'parent' argument is now always RELATIVE to user's base_path for API calls
        is_search = keywords is not None
        api_call_type = "search" if is_search else "list"
        api_keywords = keywords if is_search else ""

        # Construct the path for display (absolute) by combining base_path and relative parent
        if self.user_base_path == "/" or not self.user_base_path:
             display_path = parent
        elif parent == "/":
             display_path = self.user_base_path.rstrip('/') or "/"
        else:
             display_path = f"{self.user_base_path.rstrip('/')}/{parent.lstrip('/')}"
        display_path = re.sub(r'/+', '/', display_path) # Normalize display path

        logger.debug(f"Executing API helper - Type: {api_call_type}, API Keywords: '{api_keywords}', Page: {page}, PerPage: {per_page}, Relative Parent for API: '{parent}', Display Path: '{display_path}'")

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
                    # Use total from API if available, otherwise fallback to len(full_content)
                    total = api_data.get("total", len(full_content))
                    logger.debug(f"List directory successful. Total items reported: {total}, Fetched: {len(full_content)}")

            if api_data is None:
                action_desc = f"搜索 '{api_keywords}'" if is_search else "列出目录"
                # Show the user-friendly display path in error messages
                return f"❌ 在路径 '{display_path}' 中{action_desc}时出错或未找到结果。"

            total_pages = math.ceil(total / per_page) if per_page > 0 else 1

            if is_search:
                # For search, use the API-provided content directly (already paginated)
                display_content = full_content
            else:
                # For listing, paginate client-side from the full_content
                start_index = (page - 1) * per_page
                end_index = start_index + per_page
                display_content = full_content[start_index:end_index] if per_page > 0 else full_content

            if not display_content and total > 0: # Handle case where page is out of bounds but total > 0
                 # Show the user-friendly display path in error messages
                 return f"❎ 在路径 '{display_path}' 的第 {page} 页没有找到结果 (共 {total_pages} 页)。"
            elif not display_content:
                 action_desc = f"与 '{api_keywords}' 相关的文件" if is_search else "任何文件或文件夹"
                 # Show the user-friendly display path in error messages
                 return f"❎ 在路径 '{display_path}' 中未能找到{action_desc}。"

            # Show the user-friendly display path in the success message
            reply_text = f"✅ 在 '{display_path}' 中找到 {total} 个结果 (第 {page}/{total_pages} 页):\n"

            # Calculate overall index for display based on current page and per_page
            page_start_index_display = (page - 1) * per_page

            for i, item in enumerate(display_content):
                overall_index = page_start_index_display + i + 1 # Index relative to the whole list/search
                is_dir = item.get("is_dir", False)
                item_type = "📁" if is_dir else "📄"
                size_str = self._format_size(item.get("size", 0)) if not is_dir else ""
                name = item.get('name', '未知名称')
                reply_text += f"\n{overall_index}. {item_type} {name} {'('+size_str+')' if size_str else ''}"
                if not is_dir and client:
                    link = None
                    raw_url = item.get("raw_url")
                    name = item.get('name', '未知名称')
                    sign = item.get("sign") # Check for sign first

                    try:
                        if raw_url and isinstance(raw_url, str) and raw_url.startswith(('http://', 'https://')):
                            # 1. Use raw_url if available and looks valid
                            logger.debug(f"Using raw_url for {name}: {raw_url}")
                            link = raw_url
                        else:
                            # 2. Construct link manually, differentiating between search and list/browse
                            encoded_path_for_link = ""
                            true_absolute_path = "" # Path relative to Alist root needed for the /d/ link

                            if is_search:
                                # For search results, use item's parent (usually absolute)
                                item_parent_path = item.get("parent", "/")
                                if item_parent_path == "/":
                                    true_absolute_path = f"/{name}"
                                else:
                                    true_absolute_path = f"{item_parent_path.rstrip('/')}/{name}"
                                # Normalize slashes
                                true_absolute_path = re.sub(r'/+', '/', true_absolute_path)
                                logger.debug(f"Link Gen (Search) - Item Parent: '{item_parent_path}', True Absolute Path: '{true_absolute_path}'")
                            else:
                                # For list/browse results, combine base_path + relative parent + name
                                current_dir_relative_to_base = parent # 'parent' arg is relative for list/browse
                                # Combine current dir (relative to base) and name
                                if current_dir_relative_to_base == "/":
                                     item_path_relative_to_base = f"/{name}"
                                else:
                                     item_path_relative_to_base = f"{current_dir_relative_to_base.rstrip('/')}/{name}"
                                # Combine user's base_path and the item's relative path for true absolute path
                                if self.user_base_path == "/":
                                     true_absolute_path = item_path_relative_to_base
                                else:
                                     # Ensure no double slashes when joining base and relative paths
                                     true_absolute_path = f"{self.user_base_path.rstrip('/')}/{item_path_relative_to_base.lstrip('/')}"
                                # Normalize slashes
                                true_absolute_path = re.sub(r'/+', '/', true_absolute_path)
                                logger.debug(f"Link Gen (List/Browse) - User Base: '{self.user_base_path}', Current Dir Rel: '{current_dir_relative_to_base}', True Absolute Path: '{true_absolute_path}'")

                            # Encode the final absolute path
                            encoded_path_for_link = quote(true_absolute_path)

                            # Construct the base link using the correctly determined encoded path
                            base_link = f"{client.host}/d{encoded_path_for_link}"

                            if sign:
                                # Append sign if available
                                logger.debug(f"Using sign for {name}: {sign}")
                                link = f"{base_link}?sign={sign}"
                            else:
                                # Fallback to unsigned link
                                if self.user_base_path and true_absolute_path.startswith(self.user_base_path):
                                    file_abs_path = true_absolute_path[len(self.user_base_path):].lstrip('/')
                                else:
                                    file_abs_path = true_absolute_path
                                file_info = await client.get_file_info(file_abs_path)
                                sign = file_info.get("sign")
                                if sign:
                                    link = f"{base_link}?sign={sign}"
                                else:
                                    logger.debug(f"No sign found for {name}, using unsigned link.")
                                    link = base_link

                        # Add the generated link or an error message
                        if link:
                            reply_text += f"\n  Link: {link}"
                        else:
                             reply_text += f"\n  (无法生成下载链接)"

                    except Exception as link_e:
                        logger.error(f"Error generating link for {name}: {link_e}", exc_info=True)
                        reply_text += f"\n  (生成链接时出错)"

            if total_pages > 1:
                reply_text += f"\n\n📄 使用 /al np 翻页 (下一页), /al lp 翻页 (上一页)。 (共 {total_pages} 页)"
            if any(item.get("is_dir") for item in display_content):
                reply_text += "\n\n➡️ 使用 /al fl <序号> 进入文件夹。"
            # Add return command hint if history exists
            sender_id = event.get_sender_id()
            if sender_id and sender_id in self.last_search_state and len(self.last_search_state.get(sender_id, [])) > 0:
                 reply_text += "\n↩️ 使用 /al r 返回上一级。"


            # --- State Saving Logic ---
            if sender_id:
                # Get or initialize the state history list for the user
                user_history = self.last_search_state.setdefault(sender_id, [])

                new_state = {
                    "keywords": keywords,
                    "results": display_content, # Store only the *displayed* content for folder navigation
                    "parent": parent, # Store the RELATIVE path used for the API call
                    "current_page": page,
                    "total_pages": total_pages,
                    "timestamp": time.time(),
                    "total": total, # Store total for pagination and folder nav checks
                }

                # Determine if the new state represents pagination or a new view
                is_new_view = True # Assume new view unless it's pagination
                if user_history:
                    last_state = user_history[-1]
                    # Check if parent, keywords (if any), and total match the last state
                    if (last_state["parent"] == parent and
                        last_state.get("keywords") == keywords and # Use .get for keywords
                        last_state["total"] == total):
                        # It's pagination if only the page number changed significantly
                        if last_state["current_page"] != page:
                             is_new_view = False # It's pagination
                        else: # Page is the same, treat as refresh, update timestamp but don't add history
                             logger.debug(f"Same view detected for user {sender_id}, updating timestamp.")
                             last_state["timestamp"] = new_state["timestamp"]
                             is_new_view = False # Don't add to history

                if not is_new_view and user_history: # Check user_history exists before indexing
                    # Update the current page and timestamp of the last state (pagination)
                    logger.debug(f"Updating last state for user {sender_id} (pagination): page {page}/{total_pages}")
                    user_history[-1]["current_page"] = page
                    user_history[-1]["timestamp"] = new_state["timestamp"]
                    user_history[-1]["results"] = new_state["results"] # Update displayed results
                elif is_new_view: # Only append if it's genuinely a new view
                    # Append the new state, representing a new view (search, folder entry, or first view)
                    logger.debug(f"Appending new state for user {sender_id}: parent '{parent}', keywords '{keywords}', page {page}/{total_pages}")
                    user_history.append(new_state)
                    # Limit history depth
                    if len(user_history) > self.max_history_depth:
                        logger.debug(f"History limit reached for user {sender_id}, removing oldest state.")
                        user_history.pop(0) # Remove the oldest state
            else:
                 logger.warning("Could not get sender ID from event, state not stored.")

            return reply_text

        except Exception as e:
            logger.error(f"Error during API call execution/formatting: {e}", exc_info=True)
            return f"处理请求时发生内部错误，请查看日志。"

    @filter.command("al s", alias={'alist s', 'al 搜索', 'alist 搜索', 'alist search', 'al search'})
    async def search_command(self, event: AstrMessageEvent, keywords: str):
        """使用 /al s 命令在 Alist 中搜索文件。用法: /al s <关键词>"""
        # Get admin users directly as a list (assuming config provides it)
        admin_users = self.config.get("admin_users", [])
        sender_id = event.get_sender_id()
        if admin_users and sender_id not in admin_users:
            logger.warning(f"User {sender_id} is not an admin, access denied.")
            yield event.plain_result("没有权限使用此命令。")
            return
        logger.debug(f"search_command called with keywords: '{keywords}'")
        page = 1
        parent = "/"
        # Clear history before starting a new search
        if sender_id:
            logger.debug(f"Clearing history for user {sender_id} due to /al s")
            self.last_search_state[sender_id] = [] # Clear the list

        client = await self._get_client()
        if not client:
            yield event.plain_result("错误：Alist 客户端未配置或初始化失败。")
            return

        per_page = self.config.get("search_result_limit", 25)
        yield event.plain_result(f"⏳ 正在根目录 '/' 搜索 '{keywords}'...")

        result_message = await self._execute_api_call_and_format(event, client, page, per_page, parent, keywords=keywords)
        yield event.plain_result(result_message)

    @filter.command("al fl", alias={'alist fl', 'al folder', 'alist folder', 'al 文件夹', 'alist 文件夹'})
    async def folder_command(self, event: AstrMessageEvent, index_str: str):
        """进入指定序号的文件夹。用法: /al fl <序号>"""
        # Get admin users directly as a list
        admin_users = self.config.get("admin_users", [])
        sender_id = event.get_sender_id()
        if admin_users and sender_id not in admin_users:
            logger.warning(f"User {sender_id} is not an admin, access denied.")
            yield event.plain_result("没有权限使用此命令。")
            return
        logger.debug(f"folder_command called with index string: {index_str}")

        sender_id = event.get_sender_id()
        if not sender_id:
            yield event.plain_result("❌ 无法获取用户信息。")
            return
        # Check if history exists and is not empty
        if sender_id not in self.last_search_state or not self.last_search_state[sender_id]:
            yield event.plain_result("❌ 没有导航历史记录。请先使用 /al s 或 /al home。")
            return

        # Get the current state (last item in the history list)
        user_history = self.last_search_state[sender_id]
        state = user_history[-1] # Get the latest state from the list
        if (time.time() - state["timestamp"]) > self.search_state_timeout:
            yield event.plain_result("❌ 上次操作已超时 (3分钟)。请重新使用 /al s 或 /al home。")
            return

        try:
            index = int(index_str)
            # Use the total count from the state for bounds checking
            total_items_in_view = state.get("total", 0) # Total items in the view represented by state
            if not (0 < index <= total_items_in_view):
                 yield event.plain_result(f"❌ 无效的序号 '{index}'。请从 1 到 {total_items_in_view} 中选择。")
                 return

            # Adjust index for the current page's results
            per_page = self.config.get("search_result_limit", 25) # Use consistent per_page from config
            page_start_index = (state["current_page"] - 1) * per_page + 1
            relative_index = index - page_start_index
            # Check relative index against the length of the *stored* results for the current page in state
            if not (0 <= relative_index < len(state.get("results", []))):
                yield event.plain_result(f"❌ 序号 {index} 不在当前页 (第 {state['current_page']} 页) 的范围内。")
                return

            # Get the selected item from the stored results for the current page in the state
            selected_item = state["results"][relative_index]
            if not selected_item.get("is_dir"):
                 yield event.plain_result(f"❌ 无法进入，序号 {index} ('{selected_item.get('name')}') 不是文件夹。")
                 return

            folder_name = selected_item.get("name")
            if not folder_name:
                 yield event.plain_result(f"❌ 无法获取序号 {index} 的文件夹名称。")
                 return

            # --- Determine the next parent path RELATIVE to user's base_path ---
            next_parent_relative = "/" # Default path relative to base_path
            was_search = state.get("keywords") is not None # Check if the *current* state was from a search

            if was_search:
                # If navigating from search, item['parent'] is absolute. Need to make it relative to base_path.
                item_parent_absolute = selected_item.get("parent", "/")
                # Construct the full absolute path of the folder being entered
                item_full_absolute = os.path.join(item_parent_absolute, folder_name).replace("\\", "/")
                item_full_absolute = re.sub(r'/+', '/', item_full_absolute) # Normalize

                if self.user_base_path == "/":
                    next_parent_relative = item_full_absolute
                elif item_full_absolute.startswith(self.user_base_path):
                    # Strip base_path prefix to get the relative path
                    base_path_len = len(self.user_base_path)
                    # Handle base_path potentially having or not having a trailing slash
                    if self.user_base_path != "/" and not self.user_base_path.endswith('/'):
                         base_path_len += 1 # Account for the implicit slash in the absolute path

                    if len(item_full_absolute) >= base_path_len: # Use >= to handle entering base path itself
                         next_parent_relative = "/" + item_full_absolute[base_path_len:].lstrip('/')
                    else: # Should not happen if starts_with is true
                         logger.warning(f"Path calculation error (search): '{item_full_absolute}' vs '{self.user_base_path}'")
                         next_parent_relative = "/" # Fallback

                    if not next_parent_relative.startswith("/"): # Ensure leading slash
                         next_parent_relative = "/" + next_parent_relative
                else:
                    # This case might indicate an issue or edge case (e.g., search result outside base_path?)
                    logger.warning(f"Search result item path '{item_full_absolute}' does not start with user base path '{self.user_base_path}'. API call might fail.")
                    # Fallback: Use the calculated absolute path, though it might fail.
                    # It's better to pass the relative path even if it seems wrong, as the API expects it.
                    # Let's recalculate relative path assuming the item_parent_absolute was meant to be relative
                    # This is a guess, the API behavior is inconsistent here.
                    if item_parent_absolute == "/":
                         next_parent_relative = f"/{folder_name}"
                    else:
                         next_parent_relative = f"{item_parent_absolute.rstrip('/')}/{folder_name}"

                logger.debug(f"Folder command from search result: item abs path '{item_full_absolute}', calculated relative path for API: '{next_parent_relative}'")
            else:
                # If navigating from list view, state['parent'] is already relative to base_path
                current_parent_relative = state["parent"] # This is relative to base_path
                if current_parent_relative == "/":
                    next_parent_relative = f"/{folder_name}"
                else:
                    next_parent_relative = f"{current_parent_relative.rstrip('/')}/{folder_name}"
                logger.debug(f"Folder command from list view: current relative parent '{current_parent_relative}', calculated next relative path for API: '{next_parent_relative}'")

            # Normalize the final relative path
            next_parent_relative = re.sub(r'/+', '/', next_parent_relative)

            # --- Call API ---
            client = await self._get_client()
            if not client:
                yield event.plain_result("❌ 错误：Alist 客户端未配置或初始化失败。")
                return

            per_page = self.config.get("search_result_limit", 25)
            # Construct the display path by prepending base_path if necessary
            if self.user_base_path == "/" or not self.user_base_path:
                 display_entering_path = next_parent_relative
            elif next_parent_relative == "/":
                 display_entering_path = self.user_base_path.rstrip('/') or "/" # Handle base path being "/"
            else:
                 # Ensure no double slashes when joining base and relative paths
                 display_entering_path = f"{self.user_base_path.rstrip('/')}/{next_parent_relative.lstrip('/')}"
            display_entering_path = re.sub(r'/+', '/', display_entering_path) # Normalize display path

            yield event.plain_result(f"⏳ 正在进入并列出 '{display_entering_path}'...")

            # Call helper with the path RELATIVE to base_path
            result_message = await self._execute_api_call_and_format(
                event, client, page=1, per_page=per_page, parent=next_parent_relative, keywords=None
            )
            yield event.plain_result(result_message)
        except ValueError:
            yield event.plain_result(f"❌ 无效的序号 '{index_str}'。请输入一个数字。")
        except IndexError:
             # Use index_str in error message as index might be invalid if conversion failed
             logger.error(f"IndexError accessing state['results'] with index string '{index_str}'. State: {state}")
             yield event.plain_result(f"❌ 内部错误：无法在缓存的结果中找到序号 {index_str}。请重试。")
        except Exception as e:
            logger.error(f"Error during folder navigation: {e}", exc_info=True)
            yield event.plain_result(f"进入文件夹时发生内部错误，请查看日志。")

    @filter.command("al home", alias={'alist home'})
    async def list_home_command(self, event: AstrMessageEvent):
        """列出 Alist 根目录的内容。用法: /al home"""
        # Get admin users directly as a list
        admin_users = self.config.get("admin_users", [])
        sender_id = event.get_sender_id()
        if admin_users and sender_id not in admin_users:
            logger.warning(f"User {sender_id} is not an admin, access denied.")
            yield event.plain_result("没有权限使用此命令。")
            return
        logger.debug("list_home_command called.")
        page = 1
        parent = "/"
        # Clear history before starting a new home listing
        if sender_id:
            logger.debug(f"Clearing history for user {sender_id} due to /al home")
            self.last_search_state[sender_id] = [] # Clear the list

        client = await self._get_client()
        if not client:
            yield event.plain_result("错误：Alist 客户端未配置或初始化失败。")
            return

        per_page = self.config.get("search_result_limit", 25)
        yield event.plain_result(f"⏳ 正在列出根目录 '/' 的内容...")

        result_message = await self._execute_api_call_and_format(event, client, page, per_page, parent, keywords=None)
        yield event.plain_result(result_message)

    @filter.command("al r", alias={'alist return', 'al return'})
    async def return_command(self, event: AstrMessageEvent):
        """返回上一级视图（文件夹或搜索结果）。"""
        # Get admin users directly as a list
        admin_users = self.config.get("admin_users", [])
        sender_id = event.get_sender_id()
        if admin_users and sender_id not in admin_users:
            logger.warning(f"User {sender_id} is not an admin, access denied for return command.")
            yield event.plain_result("没有权限使用此命令。")
            return

        logger.debug(f"return_command called by user {sender_id}")

        if not sender_id:
            yield event.plain_result("❌ 无法获取用户信息。")
            return

        # Check if history exists and has at least two states (current and previous)
        if sender_id not in self.last_search_state or len(self.last_search_state.get(sender_id, [])) <= 1:
            yield event.plain_result("❌ 没有上一级视图可以返回。")
            return

        user_history = self.last_search_state[sender_id]

        # Remove the current state
        current_state = user_history.pop()
        logger.debug(f"Returning: Removed current state: {current_state.get('parent')}, kw: {current_state.get('keywords')}")

        # Get the state to return to
        prev_state = user_history[-1]
        logger.debug(f"Returning: Previous state: {prev_state.get('parent')}, kw: {prev_state.get('keywords')}, page: {prev_state.get('current_page')}")

        # Check for timeout on the previous state
        if (time.time() - prev_state["timestamp"]) > self.search_state_timeout:
            # If the previous state timed out, clear history and inform user
            logger.warning(f"Previous state timed out for user {sender_id}. Clearing history.")
            self.last_search_state[sender_id] = []
            yield event.plain_result("❌ 上一级视图已超时 (3分钟)。请重新导航。")
            return

        # Extract parameters from the previous state
        parent = prev_state["parent"]
        keywords = prev_state.get("keywords") # May be None
        page = prev_state["current_page"]
        per_page = self.config.get("search_result_limit", 25)

        client = await self._get_client()
        if not client:
            yield event.plain_result("错误：Alist 客户端未配置或初始化失败。")
            # Restore popped state? Maybe not, let them restart.
            self.last_search_state[sender_id] = [] # Clear history on client error
            return

        yield event.plain_result(f"⏳ 正在返回到 '{parent}' (第 {page} 页)...")

        # Call the formatting function with the previous state's parameters
        # Important: This call will re-save the state we are returning to,
        # effectively just updating its timestamp if it's the same view.
        result_message = await self._execute_api_call_and_format(
            event, client, page, per_page, parent, keywords=keywords
        )
        yield event.plain_result(result_message)


    @filter.command("al np", alias={'alist np', 'al 下一页', 'alist 下一页'})
    async def next_page_command(self, event: AstrMessageEvent):
        """跳转到搜索列表结果的下一页。"""
        # Get admin users directly as a list
        admin_users = self.config.get("admin_users", [])
        sender_id = event.get_sender_id()
        if admin_users and sender_id not in admin_users:
            logger.warning(f"User {sender_id} is not an admin, access denied.")
            yield event.plain_result("没有权限使用此命令。")
            return
        sender_id = event.get_sender_id()
        if not sender_id:
             yield event.plain_result("❌ 无法获取用户信息。")
             return
        # Check if history exists and is not empty
        if sender_id not in self.last_search_state or not self.last_search_state[sender_id]:
             yield event.plain_result("❌ 没有导航历史记录。")
             return

        logger.debug(f"next_page_command called by user {sender_id}")
        user_history = self.last_search_state[sender_id]
        state = user_history[-1] # Get the current state (last item in the list)
        if (time.time() - state["timestamp"]) > self.search_state_timeout:
            yield event.plain_result("❌ 上次操作已超时 (3分钟)。请重新使用 /al s 或 /al home。")
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

        per_page = self.config.get("search_result_limit", 25)
        yield event.plain_result(f"⏳ 正在获取下一页 (第 {next_page} 页)...")

        result_message = await self._execute_api_call_and_format(event, client, next_page, per_page, parent, keywords=keywords)
        yield event.plain_result(result_message)

    @filter.command("al lp", alias={'alist lp', 'al 上一页', 'alist 上一页'})
    async def last_page_command(self, event: AstrMessageEvent):
        """跳转到搜索列表结果的上一页。"""
        # Get admin users directly as a list
        admin_users = self.config.get("admin_users", [])
        sender_id = event.get_sender_id()
        if admin_users and sender_id not in admin_users:
            logger.warning(f"User {sender_id} is not an admin, access denied.")
            yield event.plain_result("没有权限使用此命令。")
            return
        sender_id = event.get_sender_id()
        if not sender_id:
             yield event.plain_result("❌ 无法获取用户信息。")
             return
        # Check if history exists and is not empty
        if sender_id not in self.last_search_state or not self.last_search_state[sender_id]:
             yield event.plain_result("❌ 没有导航历史记录。")
             return

        logger.debug(f"last_page_command called by user {sender_id}")
        user_history = self.last_search_state[sender_id]
        state = user_history[-1] # Get the current state (last item in the list)
        if (time.time() - state["timestamp"]) > self.search_state_timeout:
            yield event.plain_result("❌ 上次操作已超时 (3分钟)。请重新使用 /al s 或 /al home。")
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

        per_page = self.config.get("search_result_limit", 25)
        yield event.plain_result(f"⏳ 正在获取上一页 (第 {prev_page} 页)...")

        result_message = await self._execute_api_call_and_format(event, client, prev_page, per_page, parent, keywords=keywords)
        yield event.plain_result(result_message)

    @filter.command("al list", alias={'alist list', 'al 列表', 'alist 列表'})
    async def list_storages(self, event: AstrMessageEvent):
        """列出所有 Alist 存储。用法: /al list"""
        # Get admin users directly as a list
        admin_users = self.config.get("admin_users", [])
        sender_id = event.get_sender_id()
        if admin_users and sender_id not in admin_users:
            logger.warning(f"User {sender_id} is not an admin, access denied.")
            yield event.plain_result("没有权限使用此命令。")
            return
        logger.debug("list_storages command called.")

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

    @filter.command("al enable", alias={'alist enable', 'al 启用', 'alist 启用'})
    async def enable_storage(self, event: AstrMessageEvent, storage_id: int):
        """启用指定的 Alist 存储。用法: /al enable <存储ID>"""
        # Get admin users directly as a list
        admin_users = self.config.get("admin_users", [])
        sender_id = event.get_sender_id()
        if admin_users and sender_id not in admin_users:
            logger.warning(f"User {sender_id} is not an admin, access denied.")
            yield event.plain_result("没有权限使用此命令。")
            return
        logger.debug(f"enable_storage command called for ID: {storage_id}")

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

    @filter.command("al disable", alias={'alist disable', 'al 禁用', 'alist 禁用'})
    async def disable_storage(self, event: AstrMessageEvent, storage_id: int):
        """禁用指定的 Alist 存储。用法: /al disable <存储ID>"""
        # Get admin users directly as a list
        admin_users = self.config.get("admin_users", [])
        sender_id = event.get_sender_id()
        if admin_users and sender_id not in admin_users:
            logger.warning(f"User {sender_id} is not an admin, access denied.")
            yield event.plain_result("没有权限使用此命令。")
            return
        logger.debug(f"disable_storage command called for ID: {storage_id}")

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

    @filter.command("al delete", alias={'alist delete', 'al 删除', 'alist 删除'})
    async def delete_storage(self, event: AstrMessageEvent, storage_id: int):
        """删除指定的 Alist 存储。用法: /al delete <存储ID>"""
        # Get admin users directly as a list
        admin_users = self.config.get("admin_users", [])
        sender_id = event.get_sender_id()
        if admin_users and sender_id not in admin_users:
            logger.warning(f"User {sender_id} is not an admin, access denied.")
            yield event.plain_result("没有权限使用此命令。")
            return
        logger.debug(f"delete_storage command called for ID: {storage_id}")

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

    @filter.command("al help", alias={'alist help', 'al 帮助', 'alist 帮助'})
    async def help_command(self, event: AstrMessageEvent):
        """显示 Alist 插件的所有命令及其用法。"""
        reply_text = "首次使用记得填写alist的地址和token\n"
        reply_text += "Alist 插件命令 (前缀 /al 或 /alist):\n"
        reply_text += "/al s <关键词> - 在 Alist 中搜索文件。\n"
        reply_text += "/al fl <序号> - 进入指定序号的文件夹。\n"
        reply_text += "/al home - 列出根目录内容。\n"
        reply_text += "/al r - 返回上一级视图。\n" # Added return command
        reply_text += "/al np - 跳转到列表结果的下一页。\n"
        reply_text += "/al lp - 跳转到列表结果的上一页。\n"
        reply_text += "/al list - 列出所有 Alist 存储。\n"
        reply_text += "/al enable <存储ID> - 启用指定的 Alist 存储。\n"
        reply_text += "/al disable <存储ID> - 禁用指定的 Alist 存储。\n"
        reply_text += "/al delete <存储ID> - 删除指定的 Alist 存储 (请谨慎使用)。\n"
        reply_text += "/al help - 显示此帮助信息。\n"
        reply_text += "\n使用示例: /al s asmr, /al fl 1, /al r, /al np, /al list, /al enable 1"
        yield event.plain_result(reply_text)
