# PledgeGuard Precision & Recall Benchmark

This directory contains scripts to measure PledgeGuard's detection accuracy
against known-secret and known-clean codebases.

## Methodology

### Recall (Detection Rate)
- **Test corpus**: Repositories with known, labeled secrets
- **Metric**: Percentage of known secrets detected
- **Goal**: >95% recall on common secret types

### Precision (False Positive Rate)
- **Test corpus**: Clean repositories with no real secrets
- **Metric**: Percentage of findings that are false positives
- **Goal**: <5% false positive rate on clean codebases

## Running the Benchmarks

### Prerequisites
```bash
# Install PledgeGuard
npm install -g pledgeguard

# Clone test corpora
git clone https://github.com/pledgeandgrow/pledgeguard-benchmark-corpus.git
```

### Recall Benchmark
```bash
# Scan the known-secrets corpus
pledgeguard scan pledgeguard-benchmark-corpus/known-secrets/ \
  --format json --report-file recall-results.json --show-all

# Compare against labeled ground truth
python3 benchmark-recall.py \
  --results recall-results.json \
  --ground-truth pledgeguard-benchmark-corpus/known-secrets/labels.json
```

### Precision Benchmark
```bash
# Scan clean codebases
pledgeguard scan pledgeguard-benchmark-corpus/clean-repos/ \
  --format json --report-file precision-results.json --show-all

# Calculate false positive rate
python3 benchmark-precision.py \
  --results precision-results.json \
  --expected-zero
```

### Performance Benchmark
```bash
# Measure scan throughput
time pledgeguard scan large-repo/ --format json --report-file /dev/null

# Calculate MB/s
python3 benchmark-perf.py --results /dev/null --repo large-repo/
```

## Published Results

Results will be published at https://pledgeguard.dev/benchmarks once
the benchmark corpus is finalized.

### Target Metrics

| Metric | Target | Current |
|---|---|---|
| Recall (common secrets) | >95% | TBD |
| Precision (clean repos) | <5% FP | TBD |
| Scan throughput | >100 MB/s | TBD |
| Cold start | <100ms | TBD |
| Binary size | <15 MB | 14.8 MB |

## Contributing

To contribute to the benchmark corpus:

1. Add labeled secret examples to `known-secrets/`
2. Add clean codebases to `clean-repos/`
3. Submit a PR with updated labels

See [CONTRIBUTING.md](../CONTRIBUTING.md) for details.
