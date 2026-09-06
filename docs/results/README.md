# Retained zoxide label-propagation results

The JSON files are copies of the completed component-budgeted zoxide execution,
not new measurements from the merged release. `manifest.json` records original
paths and SHA-256 identities.

Direct FLIRT has 339 correct and 9 incorrect evaluable names; adding the verified
family propagation gives 341 correct and 9 incorrect. Two additional names are
correct and one additional address is ambiguous-neutral. These counts describe
one zoxide run. The independent dust attempt ended before prediction due to OOM.

Large discovery/body caches and external Oxidizer installations are not included
in the default checkout. The bundled unit and golden tests remain separate from
repeating this full experiment.
