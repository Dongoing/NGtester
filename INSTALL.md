# 5g-lab 安装 / 迁移手册

把这套 4 核心网 × 3 基站实验环境部署到一台新机器所需的全部步骤。日常使用见
[`README.md`](README.md)。

---

## 0. 这套环境依赖什么（迁移前先了解）

| 依赖 | 是否随项目文件夹一起走 | 迁移时怎么办 |
|---|---|---|
| `5g-lab/` 里的配置、脚本、订阅数据 | ✅ 全在文件夹里 | 直接拷贝整个 `5g-lab/` |
| Docker 镜像（open5gs/oai/free5gc/… 十几个） | ❌ 不在文件夹 | 新机器跑 `scripts/pull-images.sh` 重新拉 |
| `docker_*` 本地短标签镜像 | ❌ | 同上，`pull-images.sh` 会 pull 后自动打标签 |
| kind / helm 二进制（`tools/`） | ⚠️ 自带的是 Windows 版 | Windows 直接用；Ubuntu 装到 PATH 即可，脚本自动适配（§4） |
| Docker（Desktop 或 Engine） | ❌ 系统级 | 新机器要先装（§2；Windows 用 Desktop，Ubuntu 用 Engine） |
| SD-Core 的 K8s 集群（kind） | ❌ 运行时状态 | 新机器用 `sdcore-setup.sh` 重建（§6） |

> 一句话：**拷贝 `5g-lab/` 文件夹 + 装 Docker + 跑几个脚本**就能在新机器复现。
> 源码仓库（open5gs/srsRAN/OAI/free5gc/sdcore 等）是参考用的，跑这套实验**不需要**它们
> ——所有网元都用现成 Docker 镜像。

---

## 1. 目标环境（两者皆可，脚本自动适配）

- **Windows 10/11 + Docker Desktop（WSL2 后端）**：本项目当前所在环境。
- **原生 Linux（Ubuntu 22.04+）+ Docker Engine**：更省心（没有 WSL2 时钟坑、没有 Windows
  保留端口坑）。

两个平台用**同一套脚本**，`scripts/common.sh` 自动检测 OS。下面凡是分平台的地方都标了
「Windows / Ubuntu」。

硬件建议：**≥ 8 核 / 16 GB 内存 / 40 GB 空闲磁盘**（SD-Core 的 kind 集群 + 十几个镜像
比较吃资源）。

---

## 2. 装 Docker（按目标机器选一条）

脚本已做 **Windows / Ubuntu 自适应**（`scripts/common.sh` 自动检测 OS、定位 kind/helm、
原生 Linux 自动跳过时钟修复），所以两个平台用同一套脚本，只是装 Docker 的方式不同。

### 2A. Windows（Docker Desktop + WSL2）
1. 管理员 PowerShell 跑 `wsl --install`，重启。
2. 装 [Docker Desktop](https://www.docker.com/products/docker-desktop/)，设置里启用
   **Use the WSL 2 based engine**。
3. Docker Desktop → Resources 把 CPU/内存调够（建议 CPU ≥ 6、内存 ≥ 12 GB）。
4. 命令都在 **Git Bash** 里跑；没有就装 [Git for Windows](https://git-scm.com/download/win)。

### 2B. Ubuntu（Docker Engine，22.04+）
```bash
# 装 Docker Engine + compose 插件
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER    # 加入 docker 组后重新登录，免 sudo
# 装 kubectl（SD-Core 才需要）
sudo snap install kubectl --classic
```
Ubuntu 原生 Docker **不需要** WSL2，也**没有**时钟跳变和保留端口的坑，更省心。

### 验证（两个平台通用）
```bash
docker version          # Server 能显示版本即可
docker compose version  # 需 v2.14+
```

---

## 3. 获取项目文件

从 GitHub 克隆（推荐）：
```bash
git clone <你的仓库地址> 5g-lab
cd 5g-lab
```
或把整个 `5g-lab/` 文件夹拷到新机器（U 盘 / 网盘均可）。

以下命令都在 `5g-lab/` 目录下执行：**Windows 用 Git Bash，Ubuntu 用普通终端**。

> 换行符：仓库已带 `.gitattributes` 强制 `*.sh`/`*.yaml`/`*.env` 用 LF，正常 `git clone`
> 不会有 `bad interpreter ^M` 问题。若是用 U 盘从 Windows 拷到 Ubuntu（没走 git），再手动转一次：
> ```bash
> find . \( -name '*.sh' -o -name '*.yaml' -o -name '*.env' \) -exec sed -i 's/\r$//' {} +
> ```

---

## 4. 装 kind / helm（仅 SD-Core 需要）

只跑 Open5GS/OAI/free5GC 可跳过本节；要用 SD-Core 才需要。脚本用 `find_tool` 定位：
**先找 PATH，再找 `tools/` 下的二进制**，所以两个平台都行。

### 4A. Windows
`kind.exe` / `helm.exe` 体积大（helm ~56MB），**不随 git 仓库分发**（见 `.gitignore`）。
`git clone` 后 `tools/` 为空，首次用 SD-Core 前先下载到 `tools/`：
```bash
mkdir -p tools && cd tools
curl -sL -o kind.exe https://github.com/kubernetes-sigs/kind/releases/latest/download/kind-windows-amd64
curl -sL -o helm.zip https://get.helm.sh/helm-v3.16.4-windows-amd64.zip && unzip -oq helm.zip && mv windows-amd64/helm.exe . && rm -rf windows-amd64 helm.zip
cd ..
```

### 4B. Ubuntu
装到 PATH（推荐），脚本会自动优先用 PATH 里的：
```bash
# kind
curl -sLo /tmp/kind https://github.com/kubernetes-sigs/kind/releases/latest/download/kind-linux-amd64
sudo install -m 755 /tmp/kind /usr/local/bin/kind
# helm
curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
kind version && helm version --short
```
> 或者：把 Linux 版二进制放到 `tools/kind`、`tools/helm`（无 `.exe` 后缀），脚本也能找到。

---

## 5. 拉取镜像

```bash
./scripts/pull-images.sh            # 拉全部（十几个镜像，第一次较慢）
# 或按需分组： ./scripts/pull-images.sh base|oai|free5gc|infra
```
- 需要能访问 `ghcr.io` 和 `docker.io`。国内网络若拉不动，配代理或镜像加速器
  （Windows：Docker Desktop 设置里配；Ubuntu：改 `/etc/docker/daemon.json`）。
- SD-Core 的镜像（`ghcr.io/omec-project/*`）不在这里 —— 由 kind 集群在 helm 部署时自动拉。

---

## 6. 首次启动

### 6.1 先修时钟（仅 Windows/WSL2，每次 WSL/Docker 重启后跑一次）

```bash
./scripts/fix-clock.sh
```
- **Windows**：不修的话 WSL2 时钟每 ~30s 跳 ~2s，5G 基站会反复 "Radio link failure"、UE
  掉线。原理见 README 第 6.4 节。
- **Ubuntu**：脚本会自动检测到是原生 Linux 并跳过（跑了也无害），无需关心。

### 6.2 docker 核心网（Open5GS / OAI / free5GC）—— 开箱即用

```bash
./scripts/core.sh up open5gs             # 启动 + 自动灌 10 个订阅
./scripts/ran.sh  up ueransim open5gs    # 挂 gNB+UE
docker exec ueransim-open5gs-ueransim-ue-1 ping -I uesimtun0 -c 3 8.8.8.8
./scripts/ran.sh  down ueransim open5gs
./scripts/core.sh down open5gs
```
把 `open5gs` 换成 `oai` / `free5gc` 即换核心网，其余命令不变。首次会自动创建共享网络
`net-5glab`。

### 6.3 SD-Core（kind + Helm）—— 多两步

```bash
./scripts/sdcore-setup.sh          # 一次性节点准备（建 kind 集群、装 CNI、macvlan 网关、no-NAT 规则）
./scripts/core.sh up sdcore        # helm 部署，等 16 个 pod 全 Running：
./scripts/core.sh ps sdcore        #   反复看，直到全部 Running、upf-0 是 5/5
./scripts/ran.sh  up ueransim sdcore   # 自动把当前 AMF pod IP 写进 sdcore.env 再挂基站
```
> 首次 helm 部署要等 containerd 拉 SD-Core 镜像（几分钟）。若 pod 卡在 `ImagePullBackOff`
> 且宿主开了代理，`sdcore-setup.sh` 已处理 containerd 代理；否则稍等重试。

---

## 7. 迁移到原生 Linux 的差异

Linux 上这套更稳（无 WSL2 时钟坑、无 Windows 保留端口坑），差异：

| 项 | Windows(WSL2) | 原生 Linux |
|---|---|---|
| 时钟修复 | 必须 `fix-clock.sh` | **不需要**（脚本自动检测并跳过，跑了也无害） |
| Windows 保留端口 | 要避开（如 9800） | 无此问题 |
| kind/helm 定位 | `tools/*.exe`（自带） | 装到 PATH 或放 `tools/kind`、`tools/helm`；**脚本自动适配，无需改代码** |
| free5GC UPF | 用 eUPF（无 gtp5g 模块） | 可继续用 eUPF；若装了 gtp5g 内核模块也可换回官方 UPF |
| 脚本换行符 | 从 Windows 拷来可能是 CRLF | 拷贝后先 `find 5g-lab \( -name '*.sh' -o -name '*.yaml' \) -exec sed -i 's/\r$//' {} +` |

---

## 8. 迁移后验证清单

逐项确认迁移成功：

- [ ] `docker images | grep docker_open5gs` 有 `docker_open5gs`（pull-images 成功）
- [ ] `./scripts/core.sh up open5gs` 后 `./scripts/core.sh ps open5gs` 全部 Up
- [ ] UERANSIM UE 能 `ping 8.8.8.8`（Open5GS）
- [ ] 换 `oai` / `free5gc` 同样能通
- [ ] `./scripts/sdcore-setup.sh` + `core.sh up sdcore` 后 16 pod Running、upf 5/5
- [ ] `./scripts/ue.sh up ueransim open5gs 4` 能同时挂 4 个额外 UE 并各自 ping 通

---

## 9. 卸载 / 清理

```bash
# 停所有基站和核心网（core.sh 会自动用对的 kind/helm，跨 OS）
./scripts/ue.sh down ueransim open5gs 2>/dev/null
for c in open5gs oai free5gc; do ./scripts/core.sh down $c; done
./scripts/core.sh down sdcore                     # = helm uninstall sd-core

# 删 kind 集群（Windows 用 tools/kind.exe，Ubuntu 用 PATH 里的 kind）
source scripts/common.sh; "$KIND_BIN" delete cluster --name sdcore

# 删共享网络和数据卷
docker network rm net-5glab 2>/dev/null
docker volume rm o5gs_mongodbdata f5gc_dbdata 2>/dev/null

# 删镜像（可选，释放磁盘）
docker images --format '{{.Repository}}:{{.Tag}}' | grep -E 'docker_open5gs|docker_ueransim|docker_srs|oaisoftware|free5gc/|edgecomllc/eupf' | xargs -r docker rmi
```
