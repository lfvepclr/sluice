//! bench 冒烟测试：小规模采样跑通五场景，断言报告字段齐全。

use std::path::PathBuf;

use sluice::bench::{self, Opts};

fn smoke_opts() -> Opts {
    Opts {
        warmup: 2,
        n_small: 20,
        n_big: 2,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn five_scenarios_produce_complete_report() {
    let out = std::env::temp_dir().join(format!("sluice-bench-smoke-{}.md", std::process::id()));

    bench::run(&out, smoke_opts())
        .await
        .expect("bench 应能完整跑通");

    let report = std::fs::read_to_string(&out).expect("报告应存在");

    // 五个场景都要出现
    for name in ["B1", "B2", "T1", "T2", "T3"] {
        assert!(
            report.contains(&format!("| {name} |")),
            "报告缺少场景 {name}：\n{report}"
        );
    }

    // 报告结构字段
    for section in [
        "## 环境",
        "## 小 payload",
        "## 大 payload",
        "## 结论",
        "## 方法",
    ] {
        assert!(report.contains(section), "报告缺少小节 {section}");
    }
    for column in ["p50", "p95", "p99", "req/s", "TTFB", "RSS"] {
        assert!(report.contains(column), "报告缺少指标 {column}");
    }

    // 环境信息：版本与 commit
    assert!(report.contains("sluice"), "应记录版本");
    assert!(report.contains("平台"), "应记录平台");

    let _ = std::fs::remove_file(&out);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bench_writes_to_nested_directory() {
    let dir = std::env::temp_dir().join(format!("sluice-bench-nested-{}", std::process::id()));
    let out: PathBuf = dir.join("docs").join("BENCH.md");

    bench::run(
        &out,
        Opts {
            warmup: 1,
            n_small: 5,
            n_big: 1,
        },
    )
    .await
    .expect("应自动创建父目录");

    assert!(out.exists());
    let _ = std::fs::remove_dir_all(&dir);
}
