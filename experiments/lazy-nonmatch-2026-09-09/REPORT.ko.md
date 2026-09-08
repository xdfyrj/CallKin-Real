# F6 lazy nonmatch 실측 보고서

실험일: 2026-09-09
대상: 보존된 zoxide formal run, F5 consensus3 `k=16` 원본 큐 10,033쌍

## 판정

`normalized_instructions[*].mnemonic_class`의 실제 정규화 mnemonic multiset Jaccard가 F6 구조 일치 임계값 `0.95`보다 작으면, 해당 쌍은 F6 `MATCH`가 될 수 없다는 값싼 증명을 적용했다. 원본 큐에서 비교 가능한 8,759쌍 중 738쌍(8.4256%)이 증명되었고, instruction-count product 비용 25,839,838 중 18,940,078(73.2980%)을 F4 정렬 전에 제거할 수 있었다. raw disassembly `mnemonic`은 사용하지 않았다.

원본 큐의 candidate pair tri-state 결정은 eager/lazy가 10,033/10,033쌍에서 같았다. 두 실행 모두 자원 제한 안에서 완료했지만 최종 partition은 같지 않았다. eager는 accepted 134 families / 475 members, lazy는 134 families / 491 members였고, lazy-only accepted members는 16개이다. 현재 구현은 detailed-comparison 10,000회 ceiling을 공유한다. lazy가 738회의 cheap certificate를 비용으로 세지 않으면서 complete-link on-demand 비교를 더 진행했기 때문에, finite budget에서 실행할 수 있는 추가 비교와 성공하는 병합이 달라져 최종 partition이 달라진다. 따라서 이번 실측은 "candidate tri-state 동등성 + lazy 자원 절감"을 확인했으며 "최종 partition 동등성"은 확인하지 못했다.

비교 예산을 늘린 test-only 50k 실행도 두 실행 모두 274/252 blocked merges에서 ceiling에 도달해 전체 partition parity의 증거로 사용하지 않았다. 공통 평가쌍 51,139개에서는 decision 차이 0, 공통 MATCH numeric feature 차이 0이었지만, 최종 partition은 여전히 달랐다.

## 64-function certificate branch

cheap path를 실제로 실행하기 위해 instruction-product와 pair ID로 정렬한 가장 싼 `<0.95` 후보 `FUN_0015aba6`--`FUN_001ca7d4`(product 2)를 seed로 삼고, 그 candidate component에서 62개를 BFS한 뒤 64개까지 채웠다. 이 induced queue는 878개 후보쌍이다. eager/lazy 모두 1,959개 평가, blocked merge 0으로 완료했다. lazy는 6개 cheap nonmatch를 인증했다. candidate decision 878/878, common evaluated decision 1,959/1,959, 공통 MATCH feature dictionary 차이 0, 최종 partition 동등(`1 family / 63 members`)이었다. 이 bounded check는 certificate가 포함된 실제 semantic parity 검증이며 전체 binary에 대한 일반화 주장은 아니다. eager/lazy wall time과 RSS는 각각 `15.62 s / 4,604,780 KiB`, `16.10 s / 4,604,544 KiB`다. 상세 결과는 `results/comparison-subset64-cert.json`이다.

## 비용 계층

| 단계 | comparisons | alignment-cell proxy | 상태 |
|---|---:|---:|---|
| 보존 formal 결과(기존 adapter) | 10,033 | 15,092,410,574 | budget-refused |
| 현재 eager preflight | 8,759 | 25,839,838 | within budget |
| 현재 lazy preflight | 8,021 detailed + 738 certificate | 6,899,760 detailed | within budget |
| 현재 eager 실제 F6 | 10,000 detailed | 25,842,303 | completed |
| 현재 lazy 실제 F6 | 10,000 detailed | 6,903,974 | completed |

보존 formal의 15,092,410,574는 현재 구현의 수치가 아니다. 당시 adapter에는 `opaque_indirect_jump_count`를 F6가 읽는 `opaque_indirect_jumps` 이름으로 연결하는 alias가 없어서 opaque 쌍 1,274개가 detailed 비용으로 가격화되었다. 그 opaque 쌍의 product만 15,066,570,736이다. 현재 adapter는 이를 제외하므로 1,274쌍은 `ABSTAIN`이고 8,759쌍만 F4 비용 대상이다. 이 구분으로 historical refusal, current eager, new lazy를 섞지 않았다.

현재 eager eligible product의 median/max는 `1 / 3,030,112`, top-10 share는 `41.9905%`, top-50 share는 `69.1484%`다. lazy certificate 뒤 남은 uncertified product는 `6,899,760`이고 median/max는 `1 / 629,642`다. 보존 formal 전체 product의 max는 `1,257,569,953`, top-10 share는 `63.8155%`였다.

## 자원과 입력 무결성

production 10k와 bounded subset 실행은 CPython 3.12.3, 600초 timeout, 12 GiB address-space cap에서 완료했다. 최종 committed-code production 10k의 단일 관측 wall time/RSS는 eager `46.09 s / 4,604,928 KiB`, lazy `23.60 s / 4,604,820 KiB`이며, 이를 일반적인 speedup으로 해석하지 않는다. family outputs는 ignored `results/`에 보존하고 gzip으로도 고정했다. body cache나 binary는 실험 디렉터리에 복사하지 않았다. 각 실행의 runtime/RSS, input/code hashes는 `results/f6-10k-final.resources.json`과 `results/f6-subset64-cert.resources.json`에 기록했다.

입력 SHA-256:

- binary: `3c07eb724eefb1bc5052c3cdf3e8597f9c51eb42a9b09b86265d9994bc8bbf83`
- body: `de5b5409110c9a99c4039603f62446b07a94e04ab894acf33bf52adf77cf4805`
- candidate queue: `077c1cfbf22b7e82c13c1703a77e17d1f3bec4b82ef2356a421969fe01837161`
- formal config: `77f394244c67b6633698e80af5265da4544c8ad5033aff7d0474a5ff8f1eebfa`
- code at F6 runs: `v1_grouping.py=49369a2f0766be0c5a1664bf58709a7f1168c606ebecaade8bef10d06394cf6a`, `frozen_v1/v1_engine.py=2d96893ca22dbc3a715d1fc1fa411a2b35fafe587cad652a084a8defab5f9886`, `real_v1_adapter.py=e99b39145959f2ca8ee0aa4c6bb32c65b62f0dc5dfaa45bf36bbac379f69adb0`

## 재현 산출물

- `scripts/measure.py`: baseline 및 eager/lazy compact 비교 driver
- `results/baseline-v2.json`: actual normalized counter, comparability, cost tail, input/resource hash
- `results/comparison-10k-final.json`: final committed-code production 10k 비교
- `results/subset-64-cert.metadata.json`: certificate-bearing deterministic subset selection and hashes
- `results/comparison-subset64-cert.json`: certificate-bearing bounded semantic parity
- `results/f6-10k-final.resources.json`, `results/f6-subset64-cert.resources.json`: completed-run runtime/RSS and code hashes
- eager family SHA-256: `a7f30e8e9fc5f2576983251dfe166504731363766ee494a784f5bf4b1c6c61d9`
- lazy family SHA-256: `f8416b79ce1c912abbd95a45647f58b5e55a0b0fb6c0363f0071aa48018f710c`
- certificate subset eager family SHA-256: `c76bd9124cd4ed4ba9841bf36ab7bf91627fd6ddcebc78a9e4586e4fcd552a9c`
- certificate subset lazy family SHA-256: `4f0f0717556e015e075ccde26d361adc7d7156711737be97764c9120248d7da1`

인증은 이론적 nonmatch proof이며 full F4 score 자체를 계산했다는 뜻이 아니다. formal config의 `structure_reject_threshold`가 null이므로 `<0.95` certificate의 결정은 `UNKNOWN`이다. `==0.95`인 쌍은 certificate 대상이 아니다.
