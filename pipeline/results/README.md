# Results Archive

每个跳数的测试结果单独存放，互不干扰。
完成一个阶段后封存到这里，同时打 git tag。

## 目录结构

```
results/
├── 3hop/    ← 3跳所有链的结果（完成后封存）
├── 4hop/    ← 4跳所有链的结果（完成后封存）
└── 5hop/    ← 5跳所有链的结果（完成后封存）
```

## 封存流程

1. 某个跳数全部完成后，把 output/agent_results/COMPOSED-*.json 复制到对应目录
2. git tag vXhop-complete
3. 开新分支继续下一个跳数
