import httpx 
import asyncio 
from typing import List, Optional, Dict, Any
from urllib.parse import quote
import math
import re
import time
import os
import io 
import pathlib 
import tempfile 

from astrbot.api.event import filter, AstrMessageEvent, MessageEventResult
from astrbot.api.event.filter import event_message_type, EventMessageType 
from astrbot.api.star import Context, Star, register
from astrbot.api.message_components import Plain, Image, At
from astrbot.core.config import AstrBotConfig
from astrbot.api.message_components import File 
from astrbot.api.event import MessageChain 
import logging
from logging import FileHandler, Formatter

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
            "per_page": max(1, per_page)  
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
        if isinstance(result, dict):
             if "data" in result and isinstance(result["data"], dict):
                 logger.debug(f"/api/me returned nested data: {result['data']}")
                 return result["data"]
             elif "id" in result: 
                 logger.debug(f"/api/me returned root data: {result}")
                 return result
             else:
                 logger.warning(f"/api/me returned unexpected dict structure: {result}")
                 return None
        else:
            logger.error(f"/api/me did not return a dictionary: {result}")
            return None

    async def upload_file(self, destination_path: str, file_content: bytes, file_name: str) -> Optional[Dict[str, Any]]:
        """
        Uploads a file to the specified Alist path using /api/fs/put (streaming).

        Args:
            destination_path: The full destination path on Alist (e.g., "/mydir/myfile.txt").
                               This path should NOT be URL encoded here.
            file_content: The raw bytes content of the file to upload.
            file_name: The name of the file being uploaded (used for logging/debugging).

        Returns:
            A dictionary containing the API response on success, None on failure.
        """
        client = await self.get_client()
        encoded_path = quote(destination_path)
        upload_url = "/api/fs/put" 


        upload_headers = self.headers.copy() 
        upload_headers["File-Path"] = encoded_path

        logger.debug(f"Attempting to upload '{file_name}' to Alist path: '{destination_path}' (Encoded: '{encoded_path}')")
        logger.debug(f"Upload URL: {self.host}{upload_url}")
        logger.debug(f"Upload Headers: { {k: (v[:10] + '...' if k == 'Authorization' else v) for k, v in upload_headers.items()} }") # Mask token in log

        try:
            response = await client.put(
                upload_url,
                content=file_content,
                headers=upload_headers,
                timeout=None 
            )
            logger.debug(f"Alist Upload API Response Status: {response.status_code}")
            logger.debug(f"Alist Upload API Response Headers: {response.headers}")
            logger.debug(f"Alist Upload API Response Body: {response.text}") # Log raw response text

            response.raise_for_status() # Raise exception for 4xx/5xx responses

            try:
                data = response.json()
                logger.debug(f"Alist Upload API Response JSON Data: {data}")
                if isinstance(data, dict) and data.get("code") == 200:
                    logger.info(f"Successfully uploaded '{file_name}' to '{destination_path}'. Message: {data.get('message')}")
                    return data # Return the full response dict
                else:
                    error_message = data.get('message', 'Unknown API error') if isinstance(data, dict) else 'Invalid response format'
                    logger.error(f"Alist API error during upload ({destination_path}): Code {data.get('code', 'N/A')} - {error_message}. Response: {data}")
                    return None
            except Exception as json_e: # Catch JSONDecodeError or other parsing issues
                 logger.error(f"Failed to parse Alist upload response as JSON ({destination_path}): {json_e}. Response text: {response.text}")
                 # Check status code again, maybe 200 OK without JSON body means success?
                 if response.status_code == 200:
                     logger.warning(f"Upload to '{destination_path}' returned status 200 but no valid JSON body. Assuming success based on status code.")
                     # Return a generic success structure or None depending on expected behavior
                     return {"code": 200, "message": "Upload successful (assumed from status code)", "data": None}
                 else:
                     return None # Failed if not 200 and not valid JSON

        except httpx.HTTPStatusError as e:
            logger.error(f"Alist Upload HTTP Status Error ({destination_path}): {e.response.status_code}. Response: {e.response.text}")
            return None
        except httpx.RequestError as e:
            logger.error(f"Alist Upload Request Error ({destination_path}): {type(e).__name__} - {e}")
            return None
        except Exception as e:
            logger.error(f"Alist Upload unexpected error ({destination_path}): {e}", exc_info=True)
            return None

@register(
    "astrbot_plugin_alist",
    "Cline (Generated)",
    "通过机器人查看alist，支持管理存储和搜索文件",
    "1.2.2",  # Incremented version for history feature + admin fix
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

        # --- Additions for Upload ---
        self.upload_requests: Dict[tuple[str, str], Dict[str, Any]] = {} # Key: (sender_id, group_id), Value: {"timestamp": float, "path": str}
        self.upload_timeout: int = 180 # 3 minutes timeout for upload
        # --- End Additions ---

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

                try:
                    user_info = await self.alist_client.get_me()
                    if user_info and isinstance(user_info, dict):
                        base_path = user_info.get("base_path", "/")
                        # Normalize the base path
                        if not base_path: base_path = "/"
                        if not base_path.startswith("/"): base_path = "/" + base_path

                        self.user_base_path = base_path
                        logger.info(f"Successfully fetched user info. Base path set to: '{self.user_base_path}'")
                    else:
                        logger.warning(f"Failed to get valid user info from /api/me. Response: {user_info}. Using default base path '/'.")
                        self.user_base_path = "/"
                except Exception as me_e:
                    logger.error(f"Error calling /api/me: {me_e}. Using default base path '/'.", exc_info=True)
                    self.user_base_path = "/"

            except Exception as e:
                logger.error(f"Failed to create AlistClient object in async init: {e}", exc_info=True)
                self.alist_client = None
                self.user_base_path = "/"

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
        is_search = keywords is not None
        api_call_type = "search" if is_search else "list"
        api_keywords = keywords if is_search else ""

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
                    full_content = api_data.get("content") # Get content, might be None
                    # Calculate total based on API response or fetched content length
                    total_from_api = api_data.get("total")
                    if total_from_api is not None:
                         total = total_from_api
                    elif isinstance(full_content, list): # Check if full_content is a list before len()
                         total = len(full_content)
                    else:
                         total = 0 # Default to 0 if content is None or not a list
                         logger.warning(f"API response for '{parent}' had no 'total' and 'content' was not a list (content: {full_content!r}). Setting total items to 0.")
                    # Ensure full_content is a list for later processing, even if it was None
                    full_content = full_content if isinstance(full_content, list) else []
                    logger.debug(f"List directory successful. Total items reported: {total}, Fetched: {len(full_content)}")

            if api_data is None:
                action_desc = f"搜索 '{api_keywords}'" if is_search else "列出目录"
                # Show the user-friendly display path in error messages
                return f"❌ 在路径 '{display_path}' 中{action_desc}时出错或未找到结果。"

            total_pages = math.ceil(total / per_page) if per_page > 0 else 1

            if is_search:
                display_content = full_content
            else:
                # For listing, paginate client-side from the full_content
                start_index = (page - 1) * per_page
                end_index = start_index + per_page
                display_content = full_content[start_index:end_index] if per_page > 0 else full_content

            reply_text = ""
            is_empty_directory = not is_search and total == 0 and page == 1

            if not display_content and total > 0 and not is_empty_directory: # Page out of bounds
                 # Show the user-friendly display path in error messages
                 return f"❎ 在路径 '{display_path}' 的第 {page} 页没有找到结果 (共 {total_pages} 页)。" # Return early, state should not update
            elif not display_content and is_search: # Empty search results
                 action_desc = f"与 '{api_keywords}' 相关的文件"
                 # Show the user-friendly display path in error messages
                 return f"❎ 在路径 '{display_path}' 中未能找到{action_desc}。" # Return early, state should not update
            elif is_empty_directory: # Empty directory listing
                 logger.info(f"Directory '{display_path}' is empty.")
                 reply_text = f"✅ 目录 '{display_path}' 为空。\n" # Set message, but DO NOT return yet
                 # Proceed to state saving below
            elif not display_content and not is_empty_directory: # Should not happen if previous conditions are correct, but as a fallback
                 logger.warning(f"Unexpected empty display_content case for '{display_path}'. Total: {total}, Page: {page}")
                 return f"❎ 在路径 '{display_path}' 中未能找到任何内容。" # Return early

            if not is_empty_directory: # Only build the list if it's not an empty directory
                 # Show the user-friendly display path in the success message
                 reply_text = f"✅ 在 '{display_path}' 中找到 {total} 个结果 (第 {page}/{total_pages} 页):\n"

                 # Calculate overall index for display based on current page and per_page
                 page_start_index_display = (page - 1) * per_page

                 for i, item in enumerate(display_content):
                      # --- Item Formatting Loop ---
                      overall_index = page_start_index_display + i + 1 # Index relative to the whole list/search
                      is_dir = item.get("is_dir", False)
                      item_type = "📁" if is_dir else "📄"
                      size_str = self._format_size(item.get("size", 0)) if not is_dir else ""
                      name = item.get('name', '未知名称')
                      reply_text += f"\n{overall_index}. {item_type} {name} {'('+size_str+')' if size_str else ''}"
                      if not is_dir and client:
                          link = None
                          raw_url = item.get("raw_url")
                          # name = item.get('name', '未知名称') # Already got name above
                          sign = item.get("sign") # Check for sign first

                          try:
                              if raw_url and isinstance(raw_url, str) and raw_url.startswith(('http://', 'https://')):
                                  # 1. Use raw_url if available and looks valid
                                  logger.debug(f"Using raw_url for {name}: {raw_url}")
                                  link = raw_url
                              else:
                                  # 2. Construct link manually, handling search results specifically for get_file_info path
                                  encoded_path_for_link = ""
                                  true_absolute_path = "" # Path relative to Alist root needed for the /d/ link URL
                                  path_for_get_info = "" # Path potentially without base_path for get_file_info

                                  # Determine the correct absolute path for the item
                                  if is_search:
                                       # For search results, item['parent'] is the absolute parent path
                                       item_parent_path = item.get("parent", "/")
                                       if item_parent_path == "/":
                                           true_absolute_path = f"/{name}"
                                       else:
                                           true_absolute_path = f"{item_parent_path.rstrip('/')}/{name}"
                                       
                                       # --- Calculate path for get_file_info (without base_path if applicable) ---
                                       if self.user_base_path and self.user_base_path != "/" and true_absolute_path.startswith(self.user_base_path):
                                            path_for_get_info = "/" + true_absolute_path[len(self.user_base_path):].lstrip('/')
                                            path_for_get_info = re.sub(r'/+', '/', path_for_get_info) # Normalize
                                       else:
                                            path_for_get_info = true_absolute_path # Use absolute if base is "/" or path doesn't start with base
                                       logger.debug(f"Link Gen (Search) - Path for get_file_info: '{path_for_get_info}'")
                                       # --- End calculation for get_file_info path ---

                                  else:
                                       # For list results, 'parent' holds the current absolute directory
                                       current_absolute_dir = parent
                                       if current_absolute_dir == "/":
                                           true_absolute_path = f"/{name}"
                                       else:
                                           true_absolute_path = f"{current_absolute_dir.rstrip('/')}/{name}"
                                       # For list results, calculate path relative to base_path for get_file_info
                                       if self.user_base_path and self.user_base_path != "/" and true_absolute_path.startswith(self.user_base_path):
                                            path_for_get_info = "/" + true_absolute_path[len(self.user_base_path):].lstrip('/')
                                            path_for_get_info = re.sub(r'/+', '/', path_for_get_info) # Normalize
                                            if not path_for_get_info : path_for_get_info = "/" # Handle base path itself
                                       else:
                                            path_for_get_info = true_absolute_path # Use absolute if base is "/" or path doesn't start with base
                                       logger.debug(f"Link Gen (List) - Path for get_file_info: '{path_for_get_info}'")


                                  # Normalize the absolute path used for the final link URL
                                  true_absolute_path = re.sub(r'/+', '/', true_absolute_path)
                                  logger.debug(f"Link Gen - IsSearch: {is_search}, Item Name: '{name}', True Absolute Path for URL: '{true_absolute_path}'")

                                  # --- Get sign using the path RELATIVE to user base path ---
                                  sign = None # Initialize sign
                                  # Calculate the path relative to base_path for the get_file_info call
                                  path_for_get_info = true_absolute_path # Default to absolute path
                                  if self.user_base_path and self.user_base_path != "/" and true_absolute_path.startswith(self.user_base_path):
                                       path_for_get_info = "/" + true_absolute_path[len(self.user_base_path):].lstrip('/')
                                       path_for_get_info = re.sub(r'/+', '/', path_for_get_info) # Normalize
                                       if not path_for_get_info : path_for_get_info = "/" # Handle base path itself
                                  
                                  logger.debug(f"Attempting to fetch sign using path relative to base: '{path_for_get_info}' (derived from absolute: '{true_absolute_path}')")
                                  try:
                                      # Call get_file_info ONLY with the calculated relative path
                                      file_info = await client.get_file_info(path_for_get_info)
                                      if isinstance(file_info, dict) and file_info:
                                          sign = file_info.get("sign") # Get sign from the result
                                          if sign:
                                               logger.debug(f"Fetched sign for {name} using path '{path_for_get_info}': {sign}")
                                          else:
                                               logger.debug(f"get_file_info succeeded for '{path_for_get_info}' but no sign found.")
                                      else:
                                          logger.warning(f"get_file_info did not return valid data for {name} using path '{path_for_get_info}'. file_info: {file_info}")
                                  except Exception as get_info_e:
                                       logger.error(f"Error calling get_file_info for path '{path_for_get_info}': {get_info_e}", exc_info=True)
                                       # Keep sign as None if fetching fails
                                  # --- End get sign ---

                                  # --- Construct the final link URL ensuring base path is included ---
                                  # true_absolute_path should be the correct absolute path (e.g., /tera/file.txt) calculated earlier
                                  link_path_for_url = true_absolute_path
                                  
                                  # Double-check and enforce base path prefix for the final URL construction
                                  if self.user_base_path and self.user_base_path != "/" and not link_path_for_url.startswith(self.user_base_path):
                                      logger.warning(f"Final link path '{link_path_for_url}' is missing base path '{self.user_base_path}'. Force prepending for URL.")
                                      link_path_for_url = f"{self.user_base_path.rstrip('/')}/{link_path_for_url.lstrip('/')}"
                                      link_path_for_url = re.sub(r'/+', '/', link_path_for_url) # Normalize

                                  logger.debug(f"Final path used for link URL construction: '{link_path_for_url}'")
                                  # --- End final link path construction ---

                                  encoded_path_for_link = quote(link_path_for_url) # Use the ensured absolute path
                                  base_link = f"{client.host}/d{encoded_path_for_link}"
                                  if sign: # Use the sign obtained using the relative path
                                      link = f"{base_link}?sign={sign}"
                                      logger.debug(f"Generated signed link for {name}: {link}")
                                  else:
                                      link = base_link
                                      logger.debug(f"No sign fetched for {name} (used path '{path_for_get_info}' for get_info), using unsigned link.")

                              # Add the generated link or an error message
                              if link:
                                  reply_text += f"\n  Link: {link}"
                              else:
                                   reply_text += f"\n  (无法生成下载链接)"

                          except Exception as link_e:
                              logger.error(f"Error generating link for {name}: {link_e}", exc_info=True)
                              reply_text += f"\n  (生成链接时出错)"
                      # --- End Item Formatting Loop ---

            # --- Add navigation hints ---
            if total_pages > 1:
                 reply_text += f"\n\n📄 使用 /al np 翻页 (下一页), /al lp 翻页 (上一页)。 (共 {total_pages} 页)"
            # Only show folder navigation hint if there are actual folders displayed OR if it's an empty dir
            # Updated logic: Only show folder hint if there are actual folders displayed.
            if any(item.get("is_dir") for item in display_content):
                 reply_text += "\n\n➡️ 使用 /al fl <序号> 进入文件夹。"
            # Add return command hint if history exists
            sender_id = event.get_sender_id() # Get sender_id again for state saving
            if sender_id and sender_id in self.last_search_state and len(self.last_search_state.get(sender_id, [])) > 0:
                 reply_text += "\n↩️ 使用 /al r 返回上一级。"


            # --- State Saving Logic ---
            # This part should execute even for empty directories
            if sender_id:
                # Get or initialize the state history list for the user
                user_history = self.last_search_state.setdefault(sender_id, [])

                new_state = {
                    "keywords": keywords,
                    "results": display_content, # Store only the *displayed* content (empty for empty dir)
                    "parent": parent, # Store the ABSOLUTE path used for the API call
                    "current_page": page,
                    "total_pages": total_pages,
                    "timestamp": time.time(),
                    "total": total, # Store total (will be 0 for empty dir)
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
                elif is_new_view: # Only append if it's genuinely a new view (including entering an empty dir)
                    # Append the new state, representing a new view (search, folder entry, or first view)
                    logger.debug(f"Appending new state for user {sender_id}: parent '{parent}', keywords '{keywords}', page {page}/{total_pages}")
                    user_history.append(new_state)
                    # Limit history depth
                    if len(user_history) > self.max_history_depth:
                        logger.debug(f"History limit reached for user {sender_id}, removing oldest state.")
                        user_history.pop(0) # Remove the oldest state
            else:
                 logger.warning("Could not get sender ID from event, state not stored.")

            return reply_text.strip() # Return the final message (could be empty dir message or list)

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

    @filter.command("al dl", alias={'alist dl', 'al download', 'alist download'})
    async def download_command(self, event: AstrMessageEvent, index_str: str):
        """根据序号下载文件并通过 AstrBot 发送。"""
        admin_users = self.config.get("admin_users", [])
        sender_id = event.get_sender_id()
        if admin_users and sender_id not in admin_users: # Check admin_users only if it's configured
            logger.warning(f"User {sender_id} is not an admin, access denied for download command.")
            yield event.plain_result("没有权限使用此命令。")
            return
        logger.debug(f"download_command called by user {sender_id} with index string: {index_str}")

        if not sender_id:
            yield event.plain_result("❌ 无法获取用户信息。")
            return
        if sender_id not in self.last_search_state or not self.last_search_state[sender_id]:
            yield event.plain_result("❌ 没有导航历史记录。请先使用 /al s 或 /al home。")
            return

        user_history = self.last_search_state[sender_id]
        state = user_history[-1]
        if (time.time() - state["timestamp"]) > self.search_state_timeout:
            yield event.plain_result("❌ 上次操作已超时 (3分钟)。请重新使用 /al s 或 /al home。")
            return

        try:
            index = int(index_str)
            total_items_in_view = state.get("total", 0) # 使用 state 中的 total
            if not (0 < index <= total_items_in_view):
                 yield event.plain_result(f"❌ 无效的序号 '{index}'。请从 1 到 {total_items_in_view} 中选择。")
                 return

            per_page = self.config.get("search_result_limit", 25)
            page_start_index = (state["current_page"] - 1) * per_page + 1
            relative_index = index - page_start_index
            if not (0 <= relative_index < len(state.get("results", []))):
                yield event.plain_result(f"❌ 序号 {index} 不在当前页 (第 {state['current_page']} 页) 的缓存结果中。请尝试翻页或重新搜索。")
                return

            selected_item = state["results"][relative_index]

            if selected_item.get("is_dir"):
                 yield event.plain_result(f"❌ 不能下载文件夹 (序号 {index}: '{selected_item.get('name')}').")
                 return

            client = await self._get_client()
            if not client:
                yield event.plain_result("❌ 错误：Alist 客户端未配置或初始化失败。")
                return

            yield event.plain_result(f"⏳ 正在获取文件链接 (序号 {index}: '{selected_item.get('name')}')...")

            link = None
            name = selected_item.get('name', '未知名称')
            raw_url = selected_item.get("raw_url")
            sign = selected_item.get("sign") # Get sign from item first

            try:
                if raw_url and isinstance(raw_url, str) and raw_url.startswith(('http://', 'https://')):
                    logger.debug(f"Using raw_url for download: {raw_url}")
                    link = raw_url
                else:
                    # Replicate path calculation logic from _execute_api_call_and_format
                    true_absolute_path = ""
                    is_search = state.get("keywords") is not None
                    parent = state["parent"] # Parent from the state

                    if is_search:
                        item_parent_path = selected_item.get("parent", "/") # Use parent from item for search
                        if item_parent_path == "/":
                            true_absolute_path = f"/{name}"
                        else:
                            true_absolute_path = f"{item_parent_path.rstrip('/')}/{name}"
                        true_absolute_path = re.sub(r'/+', '/', true_absolute_path)
                        logger.debug(f"DL Link Gen (Search) - Item Parent: '{item_parent_path}', True Absolute Path: '{true_absolute_path}'")
                    else: # List/Browse
                        current_dir_relative_to_base = parent # 'parent' from state is relative for list/browse
                        if current_dir_relative_to_base == "/":
                             item_path_relative_to_base = f"/{name}"
                        else:
                             item_path_relative_to_base = f"{current_dir_relative_to_base.rstrip('/')}/{name}"
                        if self.user_base_path == "/":
                             true_absolute_path = item_path_relative_to_base
                        else:
                             true_absolute_path = f"{self.user_base_path.rstrip('/')}/{item_path_relative_to_base.lstrip('/')}"
                        true_absolute_path = re.sub(r'/+', '/', true_absolute_path)
                        logger.debug(f"DL Link Gen (List/Browse) - User Base: '{self.user_base_path}', Current Dir Rel: '{current_dir_relative_to_base}', True Absolute Path: '{true_absolute_path}'")

                    encoded_path_for_link = quote(true_absolute_path)
                    base_link = f"{client.host}/d{encoded_path_for_link}"

                    if sign:
                        logger.debug(f"Using sign from item for download: {sign}")
                        link = f"{base_link}?sign={sign}"
                    else:
                        # Attempt to get sign via get_file_info
                        logger.debug(f"No sign in item for {name}, attempting get_file_info...")
                        # Calculate file_abs_path for get_file_info (matching existing logic)
                        if self.user_base_path and self.user_base_path != "/" and true_absolute_path.startswith(self.user_base_path):
                             # Remove base path prefix if present and not root
                             file_abs_path = true_absolute_path[len(self.user_base_path):].lstrip('/')
                        else:
                             # Use the calculated absolute path directly if base path is root or path doesn't start with it
                             file_abs_path = true_absolute_path.lstrip('/') # Ensure no leading slash for API

                        file_info = await client.get_file_info(file_abs_path) # Use the correct path
                        # Check if get_file_info returned valid data before accessing it
                        if isinstance(file_info, dict) and file_info:
                            sign = file_info.get("sign")
                        else:
                            # Handle case where get_file_info failed or returned None/invalid data
                            logger.warning(f"get_file_info did not return valid data for {name}. file_info: {file_info}")
                            sign = None # Ensure sign remains None if fetch failed

                        if sign:
                            logger.debug(f"Found sign via get_file_info for download: {sign}")
                            link = f"{base_link}?sign={sign}"
                        else:
                            logger.debug(f"No sign found via get_file_info for {name}, using unsigned link for download.")
                            link = base_link # Fallback to unsigned if get_file_info fails or has no sign

                if not link:
                    yield event.plain_result(f"❌ 无法为文件 '{name}' 生成有效的下载链接。")
                    return

                yield event.plain_result(f"⏳ 正在下载文件 '{name}'...")
                logger.info(f"Attempting to download file: {name} from link: {link}")

                http_client = await client.get_client()
                try:
                    async with http_client.stream("GET", link, timeout=client.timeout * 10, follow_redirects=True) as response:
                        response.raise_for_status() # Check for HTTP errors

                        content_length = response.headers.get("Content-Length")
                        if content_length:
                            logger.debug(f"File size: {self._format_size(int(content_length))}")

                        file_bytes = await response.aread()
                        logger.info(f"Successfully downloaded {len(file_bytes)} bytes for {name}.")


                        temp_file = None

                        plugin_dir = pathlib.Path(__file__).parent
                        temp_dir_path = plugin_dir / "temp"
                        try:
                            temp_dir_path.mkdir(parents=True, exist_ok=True)
                            logger.debug(f"Ensured temporary download directory exists: {temp_dir_path}")

                            import tempfile # Import locally as a workaround
                            with tempfile.NamedTemporaryFile(dir=str(temp_dir_path), delete=False, suffix=f"_{name or 'download'}") as temp_file:
                                temp_file.write(file_bytes)
                                temp_file_path = temp_file.name
                                logger.debug(f"Saved downloaded content to temporary file: {temp_file_path}")

                            # Construct MessageChain with File component using the temporary file path
                            # Determine the path/URI to send to the adapter
                            adapter_path_config = self.config.get("adapter_accessible_temp_path", "").strip()
                            file_uri_to_send = ""
                            if adapter_path_config:
                                # Use the configured path + filename for the adapter
                                temp_filename = os.path.basename(temp_file_path)
                                adapter_full_path = os.path.join(adapter_path_config, temp_filename).replace("\\", "/") # Ensure forward slashes
                                file_uri_to_send = pathlib.Path(adapter_full_path).as_uri()
                                logger.debug(f"Using configured adapter path to build URI: {file_uri_to_send}")
                            else:
                                # Fallback to using the container's internal path URI (might fail)
                                file_path_obj = pathlib.Path(temp_file_path)
                                file_uri_to_send = file_path_obj.as_uri()
                                logger.warning(f"adapter_accessible_temp_path not configured. Using internal path URI (may fail in Docker): {file_uri_to_send}")

                            message_to_send = MessageChain([File(file=file_uri_to_send, name=name)])
                            await event.send(message_to_send)
                            # Add a delay to allow the client (e.g., NapCat) time to process the file
                            # before the temporary file is deleted in the finally block.
                            logger.debug("Waiting a few seconds before deleting the temporary file...")
                            await asyncio.sleep(5) # Wait 5 seconds (adjust if needed)
                            logger.info(f"Sent file {name} (from temp: {temp_file_path}) to user {sender_id}.")

                        except Exception as send_e:
                            logger.error(f"Error sending file {name}: {send_e}", exc_info=True)
                            yield event.plain_result(f"❌ 发送文件时出错。")
                        finally:
                            # Clean up the temporary file
                            if temp_file and os.path.exists(temp_file.name):
                                try:
                                    os.remove(temp_file.name)
                                    logger.debug(f"Removed temporary file: {temp_file.name}")
                                except Exception as rm_e:
                                    logger.error(f"Error removing temporary file {temp_file.name}: {rm_e}")

                except httpx.HTTPStatusError as e:
                    logger.error(f"HTTP error downloading file {name} from {link}: {e.response.status_code} - {e.response.text}")
                    yield event.plain_result(f"❌ 下载文件时出错 (HTTP {e.response.status_code})。链接可能已失效或服务器错误。")
                except httpx.RequestError as e:
                    logger.error(f"Network error downloading file {name} from {link}: {e}")
                    yield event.plain_result(f"❌ 下载文件时发生网络错误: {e}")
                except Exception as download_e:
                    logger.error(f"Unexpected error downloading/sending file {name}: {download_e}", exc_info=True)
                    yield event.plain_result(f"❌ 下载或发送文件时发生意外错误。")

            except Exception as link_e:
                logger.error(f"Error generating download link for {name}: {link_e}", exc_info=True)
                yield event.plain_result(f"❌ 生成下载链接时出错: {link_e}")
                return

        except ValueError:
            yield event.plain_result(f"❌ 无效的序号 '{index_str}'。请输入一个数字。")
        except IndexError:
             logger.error(f"IndexError accessing state['results'] with index string '{index_str}'. State: {state}")
             yield event.plain_result(f"❌ 内部错误：无法在缓存的结果中找到序号 {index_str}。请重试。")
        except Exception as e:
            logger.error(f"Error during download command setup: {e}", exc_info=True)
            yield event.plain_result(f"处理下载命令时发生内部错误，请查看日志。")


    @filter.command("al ul", alias={'alist ul', 'al upload', 'alist upload'})
    async def upload_request_command(self, event: AstrMessageEvent):
        """Initiates the file upload process, requires prior navigation."""
        sender_id = event.get_sender_id()
        # Use group_id if available, otherwise use sender_id (for private chats) - consistent with handle_message
        group_id = event.get_group_id() if event.get_group_id() else sender_id
        request_key = (sender_id, group_id)

        # --- Check for navigation history ---
        user_history = self.last_search_state.get(sender_id)
        if not user_history:
             logger.warning(f"User {sender_id} attempted 'al ul' without prior navigation.")
             yield event.plain_result("❌ 请先导航到目标目录后再使用上传功能。")
             return # Stop execution if no history
        # --- End check ---

        client = await self._get_client()
        if not client:
            yield event.plain_result("❌ Alist 客户端未初始化，请检查配置。")
            return

        # --- Add logging here ---
        logger.debug(f"Determining upload path. Current self.user_base_path: '{self.user_base_path}'")
        # --- End logging ---

        # Get current path from the latest state
        # History is guaranteed to exist here due to the check above
        current_state = user_history[-1]
        # Correct key is 'parent' based on state saved in _execute_api_call_and_format
        current_path = current_state.get("parent", self.user_base_path) # Fallback just in case state is malformed
        logger.debug(f"History found for {sender_id}, using current parent path: {current_path}")

        # Store the upload request
        timestamp = time.time()
        self.upload_requests[request_key] = {
            "timestamp": timestamp,
            "path": current_path
        }
        logger.info(f"Upload request initiated for user {sender_id} in group {group_id} for path '{current_path}'. Waiting for file...")

        # Clean up expired requests before sending confirmation
        await self._cleanup_expired_uploads()

        # Send confirmation message using yield
        yield event.plain_result(f"⏳ 请在 {self.upload_timeout // 60} 分钟内发送要上传到 '{current_path}' 的文件。")

        # Stop event propagation after successfully initiating the request
        event.stop_event()
        return

        # Clean up expired requests (optional, can be done here or in handle_message)
        await self._cleanup_expired_uploads()

        # Send confirmation message using yield
        yield event.plain_result(f"⏳ 请在 {self.upload_timeout // 60} 分钟内发送要上传到 '{current_path}' 的文件。")

        # Clean up expired requests (optional, can be done here or in handle_message)
        await self._cleanup_expired_uploads()

        yield event.plain_result(f"⏳ 请在 {self.upload_timeout // 60} 分钟内发送要上传到 '{current_path}' 的文件。")

    async def _cleanup_expired_uploads(self):
        """Removes expired upload requests."""
        now = time.time()
        # Create a list of keys to avoid modifying dict during iteration
        expired_keys = [
            key for key, data in self.upload_requests.items()
            if now - data.get("timestamp", 0) > self.upload_timeout
        ]
        for key in expired_keys:
             # Use pop to safely remove the key, handling potential race conditions
             removed_data = self.upload_requests.pop(key, None)
             if removed_data: # Log only if a key was actually removed
                 logger.info(f"Removed expired upload request for key: {key}")

    # This method needs proper registration within AstrBot's event system.
    # Use @event_message_type based on documentation to receive messages.
    @event_message_type(EventMessageType.ALL) # Use decorator imported from filter
    async def handle_message(self, event: AstrMessageEvent):
        """Handles incoming messages to check for pending file uploads."""
        # Check if the message contains a File component using event.message_obj.message
        file_component: Optional[File] = None
        # Ensure message_obj and message exist before iterating
        if event.message_obj and hasattr(event.message_obj, 'message') and isinstance(event.message_obj.message, list):
             for element in event.message_obj.message:
                 if isinstance(element, File):
                     file_component = element
                     break # Found the first file
        else:
             # Log if message structure is unexpected, but continue processing other handlers
             logger.debug(f"Event message_obj or message attribute missing/invalid for event: {type(event)}. Skipping file check.")
             return # Allow event propagation

        if not file_component:
            # logger.debug("Message does not contain a File component, skipping upload check.")
            # Not a file message, let other handlers process it
            return # Allow event propagation

        # --- It is a file message, proceed with upload check ---
        sender_id = event.get_sender_id()
        # Use group_id if available, otherwise use sender_id (for private chats)
        group_id = event.get_group_id() if event.get_group_id() else sender_id
        request_key = (sender_id, group_id)

        logger.debug(f"Received message with File component from {sender_id}/{group_id}. Checking for pending upload request.")

        # Clean up expired requests first
        await self._cleanup_expired_uploads()

        # Check if there's a pending upload request for this user/group
        # Use get() first to check without removing, then pop() if we decide to handle it.
        upload_request_info = self.upload_requests.get(request_key)

        if not upload_request_info:
            logger.debug(f"No pending upload request found for key {request_key}. Allowing event propagation.")
            # No pending request for this user/group, let other handlers process
            return # Allow event propagation

        # --- Found a pending request, handle the upload ---
        # Now remove the request as we are handling it
        upload_request = self.upload_requests.pop(request_key, None)
        # Double check if it was removed by another process in between get and pop (unlikely but possible)
        if not upload_request:
             logger.warning(f"Upload request for {request_key} disappeared between check and pop. Allowing event propagation.")
             return # Allow event propagation

        # Check for timeout (even though we popped, check the retrieved timestamp)
        now = time.time()
        request_time = upload_request.get("timestamp", 0)
        target_path = upload_request.get("path", "/")

        if now - request_time > self.upload_timeout:
            logger.info(f"Upload request for key {request_key} has expired (checked after retrieval).")
            # Optionally notify the user about expiration? Might be noisy.
            # await event.reply("⏰ 上传请求已超时。请重新使用 `al ul` 命令。")
            # Request expired, stop processing this event here
            event.stop_event()
            return

        # --- Process the upload ---
        logger.info(f"Processing pending upload for key {request_key} to path '{target_path}'.")
        client = await self._get_client()
        if not client:
            yield event.plain_result("❌ Alist 客户端未初始化，无法上传。")
            # Request already removed by pop
            event.stop_event() # Stop processing
            return

        try:
            # Get file details
            # Correct attribute is 'name', not 'file_name' based on logs
            file_name = getattr(file_component, 'name', 'unknown_file')
            file_id = getattr(file_component, 'file_id', None)
            file_path = getattr(file_component, 'file', None) # Get the local file path if available

            file_content = None
            logger.debug(f"Attempting to get content for file: name='{file_name}', id='{file_id}', path='{file_path}'")

            # Attempt 1: Try using file_id with event.get_file_bytes
            if file_id:
                try:
                    logger.debug(f"Attempting to get bytes using file_id: {file_id}")
                    file_content = await event.get_file_bytes(file_id)
                    if file_content:
                         logger.debug(f"Successfully retrieved {len(file_content)} bytes using file_id.")
                    else:
                         logger.warning(f"event.get_file_bytes({file_id}) returned empty content.")
                except Exception as e_get_bytes:
                    logger.warning(f"Failed to get file bytes using file_id {file_id}: {e_get_bytes}. Will try local path if available.")
                    file_content = None # Ensure content is None if get_bytes failed

            # Attempt 2: If file_id failed or wasn't present, try reading from local path
            if not file_content and file_path and isinstance(file_path, str):
                logger.debug(f"Attempting to read file from local path: {file_path}")
                try:
                    # Define sync read function for asyncio.to_thread
                    def read_local_file(path):
                        with open(path, 'rb') as f:
                            return f.read()

                    # Run synchronous file read in a separate thread
                    file_content = await asyncio.to_thread(read_local_file, file_path)
                    if file_content:
                        logger.debug(f"Successfully read {len(file_content)} bytes from local path: {file_path}")
                    else:
                        logger.warning(f"Reading local file {file_path} resulted in empty content.")
                except FileNotFoundError:
                    logger.error(f"Local file not found at path: {file_path}")
                    file_content = None
                except PermissionError:
                     logger.error(f"Permission denied when trying to read local file: {file_path}")
                     file_content = None
                except Exception as e_read_local:
                    logger.error(f"Error reading local file {file_path}: {e_read_local}", exc_info=True)
                    file_content = None

            # Final check: If no content could be obtained
            if not file_content:
                 logger.error(f"Could not retrieve file content for '{file_name}' using either file_id or local path. Upload failed.")
                 yield event.plain_result(f"❌ 无法获取文件 '{file_name}' 的内容，上传失败。")
                 event.stop_event()
                 return

            # Construct the full destination path
            current_upload_path = target_path # Path where 'al ul' was issued
            # Normalize base path '/' and join correctly
            if current_upload_path == "/":
                 destination_path = f"/{file_name.lstrip('/')}"
            else:
                 # Ensure no double slashes
                 destination_path = f"{current_upload_path.rstrip('/')}/{file_name.lstrip('/')}"

            # Normalize path separators
            destination_path = destination_path.replace('\\', '/')
            destination_path = re.sub(r'/+', '/', destination_path) # Consolidate slashes

            logger.info(f"Uploading file '{file_name}' ({len(file_content)} bytes) to Alist path: '{destination_path}'")
            yield event.plain_result(f"⏳ 正在上传文件 '{file_name}' 到 '{destination_path}'...") # Provide feedback

            upload_result = await client.upload_file(destination_path, file_content, file_name)

            # Request already removed by pop

            if upload_result and upload_result.get("code") == 200:
                logger.info(f"Successfully uploaded '{file_name}' to '{destination_path}'.")
                reply_msg = f"✅ 文件 '{file_name}' 已成功上传到 '{destination_path}'。"

                # Try to get the standard Alist download link (/d/...)
                try:
                    await asyncio.sleep(5) # Increase delay to 5 seconds

                    # --- Get file info using the ORIGINAL upload path ---
                    # destination_path is the path used for the upload API call (e.g., /2023/11/18/options.json)
                    logger.debug(f"Getting file info using original upload path: '{destination_path}'")
                    file_info = await client.get_file_info(destination_path) # Use original path
                    # --- End get file info ---

                    link = None
                    if file_info and isinstance(file_info, dict):
                         sign = file_info.get("sign") # Get the sign using the original path info

                         # --- Construct the FINAL link URL by prepending the user base path ---
                         # self.user_base_path is the base path from /api/me (e.g., /tera)
                         if self.user_base_path and self.user_base_path != "/":
                             link_path_for_url = f"{self.user_base_path.rstrip('/')}/{destination_path.lstrip('/')}"
                         else:
                             link_path_for_url = destination_path
                         link_path_for_url = re.sub(r'/+', '/', link_path_for_url) # Normalize slashes
                         logger.debug(f"Constructed final link path with base path: '{link_path_for_url}'")
                         # --- End final link path construction ---

                         # Construct the standard /d/ link using the FINAL constructed path
                         encoded_path_for_link = quote(link_path_for_url) # Use final path for URL encoding
                         base_link = f"{client.host}/d{encoded_path_for_link}"
                         if sign:
                             link = f"{base_link}?sign={sign}" # Append the sign obtained earlier
                             logger.debug(f"Generated signed link for {file_name}: {link}")
                         else:
                             link = base_link # Use unsigned link if no sign
                             logger.debug(f"Generated unsigned link for {file_name}: {link}")
                         reply_msg += f"\n🔗 下载链接: {link}"
                    else:
                         logger.warning(f"Could not get file info using original path '{destination_path}' after upload. API response: {file_info}")
                         reply_msg += f"\n⚠️ 无法获取上传文件的信息以生成下载链接。"

                except Exception as get_info_e:
                    # Use the original path in the error message for clarity on where get_file_info failed
                    logger.error(f"Error getting file info/sign after upload for original path '{destination_path}': {get_info_e}", exc_info=True)
                    reply_msg += f"\n⚠️ 获取文件签名以生成下载链接时出错。"

                yield event.plain_result(reply_msg)
            else:
                error_msg = upload_result.get("message", "上传失败，请检查日志") if upload_result else "上传失败，请检查日志"
                logger.error(f"Failed to upload file '{file_name}' to '{destination_path}'. Error: {error_msg}")
                yield event.plain_result(f"❌ 上传文件 '{file_name}' 到 '{destination_path}' 失败: {error_msg}")

            # Upload processed (success or failure), stop event propagation
            event.stop_event() # Upload processed (success or failure), stop event propagation
            return

        except Exception as e:
            logger.error(f"Error during file upload handling for key {request_key}: {e}", exc_info=True)
            yield event.plain_result(f"❌ 处理文件上传时发生内部错误: {e}")
            # Request already removed by pop
            # Stop event propagation on internal error during upload handling
            event.stop_event() # Stop event propagation on internal error during upload handling
            return



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
        reply_text += "/al dl <序号> - 按序号下载文件列表中的文件。\n"
        reply_text += "/al ul - 上传文件到文件列表中。\n"
        reply_text += "/al list - 列出所有 Alist 存储。\n"
        reply_text += "/al enable <存储ID> - 启用指定的 Alist 存储。\n"
        reply_text += "/al disable <存储ID> - 禁用指定的 Alist 存储。\n"
        reply_text += "/al delete <存储ID> - 删除指定的 Alist 存储 (请谨慎使用)。\n"
        reply_text += "/al help - 显示此帮助信息。\n"
        reply_text += "\n使用示例: /al s asmr, /al fl 1, /al r, /al np, /al list, /al enable 1"
        yield event.plain_result(reply_text)
