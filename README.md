# Multi-Center DICOM Ingest & Integrity API

多中心 DICOM 入库与完整性巡检平台。解决两个核心问题：

1. **设备在不同中心复用同一个 DICOM UID** 时，分割/引用结果可能错误地指向
   别家中心的影像。平台对每个来源中心独立、确定性地重映射所有实例标识，使跨
   中心数据在物理上无法串联。
2. **研究取数前发现磁盘上缺失或损坏的 DICOM**。平台为启用功能后入库的每个改写
   文件保存 SHA-256 指纹，提供按中心巡检 API；发现缺失或摘要不符即物理隔离，
   隔离后拒绝下载；运维人员可用中心原件经原上传入口重传修复，实例 ID、UID 映射
   与引用全部保持不变。

技术栈：**FastAPI + pydicom + SQLite（WAL 模式）**，单容器即可运行，交付
Docker Compose 环境与交互式 API 文档（Swagger UI）。

---

## 1. 核心保证

### 1.1 入库与 UID 改写

| 需求 | 实现方式 |
| --- | --- |
| 按“中心 + 原 UID”稳定生成新 UID | `new_uid = "2.25." + uuid5(固定命名空间, center + "|" + 原UID).int`，纯函数，无需查库、跨进程/重启不变（`app/uid.py`） |
| 跨中心同原 UID 不碰撞 | 中心标识参与哈希输入；同原 UID 在不同中心必然得到不同新 UID，引用永不跨中心 |
| 统一改写范围 | 顶层 Study/Series/SOP Instance UID、文件头 `MediaStorageSOPInstanceUID`、任意序列深度嵌套的 `ReferencedSOPInstanceUID`、序列内 `SeriesInstanceUID`、`FrameOfReferenceUID`、`ReferencedFrameOfReferenceUID`（递归遍历，`app/dicom_io.py`） |
| 不改写的内容 | SOP Class UID / Transfer Syntax UID 等“类别型”UID、Modality 等属性、**PixelData 像素字节**（写入后回读断言验证） |
| 仅接受 Explicit VR Little Endian | 校验文件头传输语法必须为 `1.2.840.10008.1.2.1`，否则整批 422 拒绝 |
| 引用先到、影像后到 | 引用先入库时在 `uid_mappings` 预留映射并在 `instance_references` 标记未解析；后续同中心影像到达后批量重新解析；不同中心到达的影像不会解析它 |
| 同中心同原 SOP 同字节重传 | 命中 `(center, original_sop_uid, sha256)` 唯一约束，直接复用已存对象，不产生重复行/重复文件 |
| 异字节冲突 | 同中心同原 SOP UID 但原始 SHA-256 不同 → 整批 409 拒绝 |
| 任一文件失败整批不入库 | 全部文件先在事务外解析；入库在单个 `BEGIN IMMEDIATE` 事务内完成，失败回滚，并清理已落盘的临时对象，**不存在半批可下载** |
| 并发安全 | SQLite WAL + 写事务互斥；唯一约束兜底；并发实测全部收敛 |
| 重启不变 | 映射为纯函数可离线复算，数据库、对象文件、指纹与隔离状态全部落盘到挂载卷 |
| 批量上限 | 每批最多 20 份文件（可配置） |

### 1.2 指纹、巡检、隔离与修复

| 需求 | 实现方式 |
| --- | --- |
| 保存改写后文件的 SHA-256 | `instances.stored_sha256` 记录**实际落盘的改写文件**指纹（与上传原件的 `sha256` 区分）；序列化输出经实测确定性，同输入永远得到同指纹 |
| 旧对象没有指纹 | 历史行 `stored_sha256 IS NULL`，巡检结果为 `no_fingerprint`，**绝不把当前磁盘文件哈希当作可信基准**；即使文件已被篡改也只报未建指纹，不自动隔离 |
| 按中心巡检 | `POST /api/v1/inspections/centers/{center_id}` 逐实例核对，返回实例 ID、核对状态（`ok` / `no_fingerprint` / `missing` / `digest_mismatch` / `skipped_repaired` / `quarantine_failed`）与异常原因，结果落 `inspection_runs` + `inspection_findings` 可复查 |
| 读取文件不占 SQLite 写事务 | 巡检走 **只读 URI 连接**（`mode=ro`、`query_only=ON`）做快照与哈希；只有真正执行隔离时才开启一个短 `BEGIN IMMEDIATE` 写事务 |
| 缺失即隔离 | 活动文件不存在：行置 `quarantined`，原因 `missing`，版本号 +1 |
| 摘要不符即隔离 | 活动文件哈希 ≠ 指纹：在写事务内把文件**同卷原子 rename** 到 `/data/quarantine/...`，行置 `quarantined`，原因 `digest_mismatch`；移动失败记录 `quarantine_failed` 且不改状态 |
| 隔离后下载拒绝 | 下载端点先查 `quarantine_state`，隔离中一律返回 **HTTP 423 Locked** 并提示重传修复，无论磁盘上是否还能读到文件 |
| 原件重传修复 | 同中心、同原 SOP UID、**原始 SHA-256 相同**即可经原 `POST /api/v1/batches` 入口修复（含隔离中行、文件已缺失但行未更新的中间态、以及磁盘文件已损坏的情形），或为旧对象建立指纹；**实例 ID、存储路径、UID 映射、引用全部不变**，只更新文件、指纹与生命周期状态 |
| 整批通过、完整落盘后才解除隔离 | 修复文件先写唯一 `.part` → 哈希校验 → 旧文件改名 `.bak-*` 旁置 → 原子换入 → CAS 更新行；事务提交后才清理备份与隔离副本。回滚则删除新文件并把 `.bak-*` 还原，失败或中断不暴露残件；启动时 `sweep_parts()` 清理/还原残留 |
| 迟到旧巡检不得再次隔离已修复对象 | 每行有单调递增 `state_version`；隔离与修复都是基于版本号的 compare-and-swap，且文件移动在写事务内，借助 SQLite 单写锁与修复严格排序。修复先提交则旧巡检 CAS 落空，记录 `skipped_repaired`，不重新隔离（有并发测试覆盖 missing 与 digest_mismatch 两条路径） |
| 同中心巡检互斥 | 进程内按中心加锁，重叠巡检第二个返回 409 |
| 状态与指纹重启保留 | 全部在 SQLite 与挂载卷中；重启后隔离状态、423 拒绝、修复后指纹均保留（有测试覆盖） |

---

## 2. 目录结构

```
app/
  config.py        环境变量配置（数据目录、隔离目录、UID 根、批量上限等）
  uid.py           确定性 UID 重映射（uuid5 + 2.25 根）
  dicom_io.py      DICOM 解析/校验、递归 UID 改写、序列化后回读校验
  storage.py       流式 SHA-256、原子写（.part）、备份旁置（.bak）、启动清扫
  db.py            SQLite schema/增量迁移、WAL 连接、只读连接、即时写事务
  service.py       批次原子入库、重传复用、修复、指纹建立、引用解析
  inspection.py    按中心巡检、CAS 隔离、并发修复竞争裁决
  main.py          FastAPI 路由与响应模型（含 423 下载拒绝）
scripts/
  generate_samples.py  生成合成样例（跨中心碰撞 / 引用先到 / 非法文件）
  demo.sh              对运行中的服务执行完整 HTTP 演示（含巡检/隔离/修复）
tests/             41 项 pytest（含并发、原子性、嵌套改写、巡检隔离修复、竞争）
samples/generated/ 合成 DICOM 样例
Dockerfile, docker-compose.yml, docker/entrypoint.sh
```

---

## 3. 快速开始（Docker Compose）

```bash
# 1. 生成合成样例（需要本机有 pydicom；也可直接用仓库内已生成的文件）
python3 scripts/generate_samples.py

# 2. 构建并启动
docker compose up --build -d

# 3. 健康检查
curl http://localhost:8000/healthz
# {"status":"ok"}

# 4. 打开交互式 API 文档
#    浏览器访问 http://localhost:8000/docs
```

### 一键脚本演示（覆盖全部需求场景）

Docker Compose 方式（脚本会通过 `docker compose exec` 在卷内改写一个字节）：

```bash
bash scripts/demo.sh
```

不用 Docker、直接本机起服务时，告知脚本数据目录即可：

```bash
DICOM_INGEST_DATA_DIR=./data uvicorn app.main:app --host 0.0.0.0 --port 8000 &
BASE_URL=http://localhost:8000 LOCAL_DATA_DIR=./data bash scripts/demo.sh
```

脚本依次演示：跨中心 UID 碰撞、引用先到、跨中心不解析、同中心影像到达后解析、
同字节重传复用、异字节整批 409、批次查询与下载校验像素不变、非法文件整批 422，
以及**健康巡检 → 破坏文件 → 巡检隔离 → 下载 423 → 原件重传修复 → 复检通过**。

### 不用 Docker 的本地运行

```bash
pip install -r requirements.txt
python3 scripts/generate_samples.py
DICOM_INGEST_DATA_DIR=./data uvicorn app.main:app --host 0.0.0.0 --port 8000
```

---

## 4. HTTP API 一览

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/api/v1/batches` | multipart 表单：`center_id` + `files`（1–20），原子入库；同原件重传兼具**修复**与**补建指纹**语义，响应含每文件 `action`（`insert`/`reuse`/`repair`/`fingerprint`） |
| GET | `/api/v1/batches` | 批次列表，可按 `center_id` 过滤 |
| GET | `/api/v1/batches/{batch_id}` | 批次详情 + 每个文件的原/新 UID 映射 |
| GET | `/api/v1/instances` | 实例检索（`center_id` / `original_sop_uid` / `new_sop_uid` / `quarantine_state`），含指纹与隔离状态 |
| GET | `/api/v1/instances/{id}/download` | 下载改写后的 DICOM；隔离中返回 **423** |
| GET | `/api/v1/references/pending` | 某中心的引用解析状态（`resolved=true/false`） |
| POST | `/api/v1/inspections/centers/{center_id}` | 对该中心全部实例执行一次完整性巡检，同步返回 run 结果 |
| GET | `/api/v1/inspections/runs/{run_id}` | 查询某次巡检及逐实例 finding |
| GET | `/api/v1/inspections/runs?center_id=...` | 某中心的巡检历史（新到旧） |
| GET | `/healthz` | 存活探针 |

错误语义：`422` = 文件/参数不合法（含非法 DICOM、传输语法不符、超 20 份）；
`409` = 与既有状态冲突（异字节同 UID、同中心巡检重叠）；`404` = 批次/实例/
中心/巡检不存在；`423` = 实例已隔离，下载被拒绝。

### 在 Swagger UI 中演示巡检与修复

1. `POST /api/v1/batches`：`center_id=insp-center`，选择
   `samples/generated/reference_first/image_001.dcm`，Execute 后 201。
2. `POST /api/v1/inspections/centers/insp-center`：Execute，返回
   `status=completed`、`ok_count=1`，finding 为 `ok` 且含 expected/actual 哈希。
3. 在容器/卷内把该实例存储文件翻转一个字节（路径取自
   `GET /api/v1/instances` 的 `stored_path`）。
4. 再次 Execute 巡检：`digest_mismatch_count=1`、`quarantined_count=1`。
5. `GET /api/v1/instances/{id}/download`：返回 **423** 与隔离原因。
6. 再次 `POST /api/v1/batches` 上传同一份中心原件：响应 `action=repair`、
   `repaired_count=1`，实例 id 与新 SOP UID 不变。
7. 第三次巡检：回到 `ok`；下载恢复 200。

---

## 5. 合成样例说明

`scripts/generate_samples.py` 生成的全部对象均为带 DICM 前导、文件头和真实
PixelData 的合法 Explicit VR Little Endian 文件：

- `cross_center_uid_collision/center-{a,b}/image_001.dcm`
  两个中心**复用完全相同的 Study/Series/SOP UID**，但像素值分别为 1000 与
  2000（异字节）。入库后得到两个不同的新 SOP UID，像素各自保持不变。
- `reference_first/struct_001.dcm`
  SR 对象，含三层嵌套
  （`ReferencedSOPSequence → ReferencedSeriesSequence → ReferencedSOPSequence`），
  引用一个尚未上传的影像 SOP。先上传它会产生一条未解析引用。
- `reference_first/image_001.dcm`
  被引用的影像。同中心上传后引用自动解析；别的中心上传同原 UID 影像不会解析；
  也是巡检/隔离/修复演示使用的中心原件。
- `invalid/not_a_dicom.dcm`
  非 DICOM 字节，用于演示整批拒绝。

---

## 6. 数据模型要点

- `uid_mappings`：每个 `(center, 原UID)` 一行，`present` 标识携带该 SOP 的实体
  是否已到达，支撑引用先到。
- `instances`：每个入库对象一行，含原/新三套 UID、原件 `sha256`、**改写文件
  指纹 `stored_sha256`**、存储相对路径、隔离生命周期
  （`quarantine_state` / `quarantine_path` / `quarantine_reason` /
  `quarantined_at`）、乐观并发版本 `state_version` 与
  `fingerprint_established_at`。`(center, original_sop_uid, sha256)` 与
  `new_sop_uid` 均唯一。旧库通过幂等 `ALTER TABLE` 自动加列，历史行指纹为 NULL。
- `instance_references`：引用关系与解析状态，按中心隔离。
- `batches`：仅记录成功提交的批次；被拒绝的批次不留任何记录或对象。
- `inspection_runs` / `inspection_findings`：巡检运行汇总（计数、状态、时间）
  与逐实例核对结果（状态、期望/实际哈希、原因、观测时的版本号）。

所有表在容器启动时通过 `CREATE TABLE IF NOT EXISTS` + 增量迁移幂等建表；
启动时同时清扫崩溃残留的 `.part`、还原 `.bak-*` 备份。

---

## 7. 运行测试

```bash
pip install -r requirements.txt -r requirements-dev.txt
pytest -q
# 41 passed
```

测试覆盖：UID 纯函数性质、跨中心碰撞隔离、嵌套序列改写、像素/传输语法保持、
引用先到后解析与跨中心不解析、同字节重传复用、异字节/非法文件整批回滚、
20 份上限、非 Explicit VR 拒绝、并发入库收敛，以及：

- 新入库写入改写文件指纹且与原件哈希不同；
- 健康巡检 `ok`、旧对象 `no_fingerprint`（含旧对象文件被篡改仍不被信任）；
- 缺失/摘要不符隔离、文件物理迁出存储树、下载 423、隔离过滤；
- 原件重传修复（缺失与损坏两条路径）后身份不变、复检通过、隔离副本清理；
- 异字节“修复”被 409 拒绝且保持隔离；修复后同字节重传回到 `reuse`；
- 失败批次不留残件、不解除隔离；
- 迟到巡检与修复竞争（missing 与 digest_mismatch）→ `skipped_repaired`、
  不重复隔离；同中心重叠巡检 409；
- 只读连接无法写入；隔离与指纹跨“重启”保留；启动清扫还原中断的修复备份。

---

## 8. 配置项（环境变量）

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `DICOM_INGEST_DATA_DIR` | `/data` | SQLite 库、对象文件与隔离区根目录（Compose 已挂卷） |
| `DICOM_INGEST_MAX_FILES` | `20` | 单批文件数上限 |
| `DICOM_INGEST_MAX_FILE_BYTES` | `52428800` | 单文件大小上限 |
| `DICOM_INGEST_UID_ROOT` | `2.25` | 新 UID 根（2.25 = UUID 派生 UID 的 ISO/ITU 保留根） |
| `DICOM_INGEST_BUSY_TIMEOUT_MS` | `30000` | SQLite 写锁等待超时 |

数据卷内布局：

```
/data/
  ingest.db                 # SQLite（WAL 模式，另含 -wal / -shm）
  objects/<center>/<new-sop>.<orig-sha>.dcm   # 在线改写文件
  quarantine/<center>/run-<run_id>/instance-<id>.dcm  # 隔离区（同卷原子 rename）
```
