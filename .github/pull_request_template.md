<!--
GitHub hides this comment on the rendered pull request.

Replace each `_`. `none` and `no` are real answers. Delete a line only when it does not apply, and say why on that line.

- Class: `specification`, `validation`, `serialization`, `crypto`, `protocol`, `node`, `verification`, `release`, `docs`, or `other`.
- Consensus behavior: `yes` only when this change can accept a block or transaction the network would reject, or reject one the network would accept. Name the rule. A refactor that must not do that is `no`.
- What a wrong merge does: one sentence. Name the bad outcome.
- Spec: Orange Paper clause, BIP, or `none`.
- Regression test: path and test name. `none` needs a reason. Consensus behavior `yes` with regression test `none` is the line to stop on.
- Sibling repositories: other BTCDecoded repositories this forces a change in, or `none`.
- Public claim: `yes` if the diff edits a homepage, white paper, README status line, `.github/SYSTEM_STATUS.md`, or a sentence that says governance is enforced or solved. Name the file.
- Emergency: `no`, or `tier_1_critical`, `tier_2_urgent`, or `tier_3_elevated` from `BTCDecoded/governance` `config/emergency-tiers.yml`, plus the activation record. There is no one-maintainer timeout.

Enforcement is off. The written signature count and review period are not collected here.
-->

## Governance

- **Layer:** Layer 2, `blvm-primitives`. A change here can diverge validation without a change to `blvm-consensus`.
- **Class:** _
- **Consensus behavior:** _
- **What a wrong merge does:** _
- **Spec:** _
- **Regression test:** _
- **Sibling repositories:** _
- **Public claim:** _
- **Emergency:** _

## This repository

- **Validation can diverge with blvm-consensus unchanged:** _
- **Call site:** _

<!-- Answer `yes` when a block or transaction can be valid in one crate and invalid in the other without editing `blvm-consensus`. Call site: the type or function in `blvm-consensus` that consumes this, or `none`. Written schedule, not enforced: 6 of 7, 180 days, 365 days when consensus behavior is `yes`. -->

## Reviewer focus

- _
- _

Enforcement is off. This record does not block the merge.
