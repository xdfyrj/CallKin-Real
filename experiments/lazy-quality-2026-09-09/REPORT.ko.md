# Lazy F6 cluster quality rescore

실험일: 2026-09-09

이번 결과는 보존된 eager/lazy F6 family output을 같은 GT-overlap universe에서 다시 계산한 것이다. 새 inference, build, GT inference는 없었고 1.1 GiB body cache도 읽지 않았다. 코드는 `quality.py`, 결과는 `quality.json`이다.

판정:

- eager와 lazy의 target universe는 각각 5,335개로 같았다. GT origin member와의 공통 universe는 617개, 전체 GT universe는 674개다.
- 617개 universe에서 두 실행 모두 TP 18, FP 15, FN 1,222, TN 186,283, precision 0.5455, recall 0.0145, F1 0.0283이다. linkage-neutral은 2,498쌍이며 ambiguous 2,458, duplicate 40, unresolved 0이다.
- 전체 674개 universe에서도 두 실행은 TP 18, FP 15, FN 1,224, TN 222,817, precision 0.5455, recall 0.0145, F1 0.0282로 같다. linkage-neutral은 2,727쌍이며 ambiguous 2,686, duplicate 41, unresolved 0이다.
- accepted family는 eager/lazy 모두 134개이며 member는 475/491개다. lazy-only accepted member 16개는 기존 5,335개 discovery target 안에 있었고 GT origin member map에는 없었다.
- accepted pair delta는 lazy 추가 955쌍, eager 제거 0쌍이다. correct join 0, wrong join 0, neutral 0, outside-GT 955다. 따라서 새 16개에 대한 이번 GT overlay의 correct/incorrect 판정은 없으며, outside-GT pair를 FP로 세지 않았다.

변경된 세 family는 `66 -> 79 (+13, pair +936)`, `8 -> 10 (+2, pair +17)`, `2 -> 3 (+1, pair +2)`다. 세 family의 eager/lazy GT member count는 모두 0/0이다. 공통 pair decision 11,274개는 mismatch 0이고 lazy-only 738개는 on-demand MATCH evaluation이다. 별도로 기존 candidate pair 738개는 cheap certificate로 평가되었다.

post-hoc ELF 진단은 non-stripped binary에서만 수행했다. ID bias `0x100000`을 되돌린 16개 모두 nonzero `STT_FUNC` extent 안에 있고 exact symbol start는 하나도 없었다. 13개 `FUN_00166af6` ... `FUN_00166c4e`는 `0x5f4c0 + 32362` extent의 `zoxide::cmd::cmd::Cmd as clap_builder::derive::Subcommand::augment_subcommands` 안에 있다. 이 13개 첫 instruction은 각각 indirect `call`이고 GOT slot은 `0x145e78`, RELA addend는 `1291915 (0x13b68b)`, raw relocation symbol은 `core::panicking::panic_in_cleanup`의 mangled symbol이다. 나머지는 `FUN_0017ab09`가 `0x7aad0 + 90`, `FUN_0017ab6e`가 `0x7ab30 + 95`, `FUN_00187256`가 `0x87220 + 92`의 drop-in-place extent 안에 있으며 첫 instruction은 각각 `mov`다. 이는 새 독립 함수가 확인됐다는 뜻이 아니라 내부 extent fragment 가능성을 보이는 진단이다.

점수는 normalized origin/linkage proxy다. 이 결과로 exact source truth나 일반화 성능을 주장하지 않는다.

재현 command:

```text
/mnt/c/Users/sumyr/playground/REV/CallKin/workspace/novel-source-real-venv/bin/python -B experiments/lazy-quality-2026-09-09/quality.py \
  --eager experiments/lazy-nonmatch-2026-09-09/results/eager-f6-10k-final.json \
  --lazy experiments/lazy-nonmatch-2026-09-09/results/lazy-f6-10k-final.json \
  --run-manifest /mnt/c/Users/sumyr/playground/REV/CallKin-Real/worktrees/CallKin-Real-formal-zoxide/results/formal-zoxide-2026-08-31/run.json \
  --ground-truth /mnt/c/Users/sumyr/playground/REV/CallKin/ground_truth/rust-nonstd/plain/zoxide.O3S.gt.json \
  --linkage-audit /mnt/c/Users/sumyr/playground/REV/CallKin/worktrees/v0-engine-py-frozen/results/zoxide/plain/zoxide.O3S.gt-mangled-audit.json \
  --candidate-queue /mnt/c/Users/sumyr/playground/REV/CallKin-Real/worktrees/CallKin-Real-formal-zoxide/results/formal-zoxide-2026-08-31/run.v1.consensus3.k16.candidates.json \
  --nonstripped-binary /mnt/c/Users/sumyr/playground/REV/CallKin/gt_bin/plain/zoxide.O3S.gt.bin \
  --output experiments/lazy-quality-2026-09-09/quality.json
```

입력 digest:

```text
eager prediction  a7f30e8e9fc5f2576983251dfe166504731363766ee494a784f5bf4b1c6c61d9
lazy prediction   f8416b79ce1c912abbd95a45647f58b5e55a0b0fb6c0363f0071aa48018f710c
run manifest      1395938b69d55b4fb416dfeb0d56cddc441c9f7a2984dc13cbb96b148a8f17d7
ground truth      b5e641338cd098ead94ea299b7dccd3a4ca2b8242743656762cf8f01617d967d
linkage audit     aea76c11cb78074695ea2ac4acc8f08026f61d81fa747d9d42948bf82f3da579
universe stage    43a4a990d6bd40ca03edb385f27cd74c708ae6533d02c0edddba6bf3a06d9f0b
relation stage    d203bd0c1bf2dc19a57e96764fbd394ecaee86fb872c4ca549e0d5d9e05e9896
candidate queue   077c1cfbf22b7e82c13c1703a77e17d1f3bec4b82ef2356a421969fe01837161
nonstripped ELF   a37ccf63601b2012ba0edbc2ab63d9442f4830fbb41e6b87f1c43a16f32dba7c
body stage        de5b5409110c9a99c4039603f62446b07a94e04ab894acf33bf52adf77cf4805 (manifest/prediction metadata only)
stripped ELF      3c07eb724eefb1bc5052c3cdf3e8597f9c51eb42a9b09b86265d9994bc8bbf83 (manifest/prediction metadata only)
```
