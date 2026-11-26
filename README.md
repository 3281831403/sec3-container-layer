镜像拉下来之后只核对了清单列表，某一层的压缩包被换成了恶意内容，运行起来毫无异常：镜像仍然启动，业务仍然响应，只是供应链的完整性已经失守。完整性校验的契约是：每一层都必须按清单声明的摘要算法重新计算层内容并完整比对摘要；层与清单的摘要必须互相一致；层的先后顺序必须与清单一致；同一镜像内不得重复使用同一层摘要；配置摘要必须与清单匹配；批量校验时每个镜像各自独立，前一个镜像的层不得流入后一个镜像。系统只承认两条不变量：任意一层被替换都必须导致该镜像校验失败；实际层数量必须与清单声明的层数量一致。

接口说明

parse_manifest(doc)
解析清单文档，返回 layers 与 config 两项。

check_layer_digest(layer, expected)
按 expected 声明的摘要算法重新计算 layer 的 data，并与 expected 完整比对。

check_layer_count(layers, manifest)
比较 layers 的长度与 manifest 中 layers 的长度。

check_order(layers, manifest)
比较 layers 的摘要序列与 manifest 中 layers 的序列。

check_duplicates(layers)
返回 layers 中重复出现的摘要。

check_config(config, manifest)
比较 config 的 digest 与 manifest 的 config。

validate_manifest(doc)
返回清单问题列表，覆盖层摘要缺失、层数量为零、配置摘要缺失。

image_batch(images)
逐个镜像校验，返回以镜像 name 为键的结果字典。

数据约定

清单文档是包含 layers 与 config 的字典，layers 中每一项是包含 digest 的字典，config 是包含 digest 的字典。
层对象是包含 data 与 digest 的字典，data 为字节串。
镜像对象包含 name、manifest、layers、config 四个字段。

## 字段表

| 字段 | 取值 |
| --- | --- |
| 所属领域 | 安全 |
| 子方向 | 漏洞检测与攻防 |
| 任务类型 | Bugfix |
| 语言/框架 | Python 3, pytest |
| 环境可复现等级 | 无外部依赖 |

