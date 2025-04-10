# astrbot_plugin_alist

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

一个用于 [AstrBot](https://github.com/AstrBotDevs/AstrBot) 的插件，允许用户通过聊天命令与 [Alist](https://alist.nn.ci/) 服务进行交互，实现文件浏览、搜索和存储管理等功能。

## ✨ 功能特性

*   **文件/目录浏览与搜索:**
    *   `/al s <关键词>`: 在 Alist 中搜索文件或目录。
    *   `/al fl <序号>`: 进入搜索结果或目录列表中的指定序号的文件夹 (别名: `/al folder`, `/al 进入` 等)。
    *   `/al home`: 列出 Alist 的根目录内容 (别名: `/alist home`)。
    *   `/al np` / `/al lp`: 对搜索结果或目录列表进行翻页 (别名: `/al 下一页`, `/al 上一页` 等)。
    *   结果会显示编号、类型（文件/文件夹）、名称、大小（文件）。
    *   文件条目会附带直接下载链接。
*   **存储管理:**
    *   `/al list`: 列出所有已配置的 Alist 存储及其状态 (别名: `/al 列表` 等)。
    *   `/al enable <存储ID>`: 启用指定 ID 的存储 (别名: `/al 启用` 等)。
    *   `/al disable <存储ID>`: 禁用指定 ID 的存储 (别名: `/al 禁用` 等)。
    *   `/al delete <存储ID>`: 删除指定 ID 的存储 (请谨慎使用) (别名: `/al 删除` 等)。
*   **帮助:**
    *   `/al help`: 显示所有可用命令及其用法 (别名: `/al 帮助` 等)。


## 🔧 配置


    Alist API 地址: "YOUR_ALIST_URL"  # 必填：您的 Alist 服务地址，例如 https://alist.example.com 或 http://192.168.1.100:5244
    Alist API Token: "YOUR_ALIST_API_TOKEN" # 必填：用于访问 Alist API 的令牌
    文件列表单页数量: 10 # 可选：每次搜索或列目录时每页显示的项目数量，默认为 10
    API 请求超时时间 (秒): 10 # 可选：连接 Alist API 的超时时间（秒），默认为 10



## 🚀 使用方法

    /al或 /alist 

*   搜索根目录下的 "电影":
    /al s 电影
*   列出alist的根目录:
    /al home`
*   进入上一条命令结果中的第 3 个文件夹:
    /al fl 3`
*   翻到下一页:
    /al np`
*   列出所有存储:
    /al list`
*   启用 ID 为 5 的存储:
    /al enable 5
*   获取帮助:
    /al help
