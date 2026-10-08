# HiveSeatVault

Custody vault for **Project Hive**'s identity.md seat NFTs. Seats keep running and earning, but can only
leave through the owner — a **48h OpenZeppelin TimelockController** — so no seat can be moved or sold
without a public, on-chain delay.

**Status: under audit — do not deploy from this repo until the audit is complete.**

- `src/HiveSeatVault.sol` — the vault (non-upgradeable, Solidity 0.8.26, OpenZeppelin 5.1)
- `test/HiveSeatVault.t.sol` — 19 unit tests (every invariant + the anti-rug attack)
- `test/HiveSeatVaultFork.t.sol` — live-mainnet fork tests: the ERC-1271 pairing digest is proven
  byte-identical to the audited IMDSeatStrategy, so IMD accepts the vault as a seat's signer.

## Design

- **Scoped operator** (`seatOperator`) pairs / runs / registers seats via ERC-1271, but has **no** path to transfer, approve, or sell one.
- **Earnings** sweep freely to a fixed `rewardSink` (reverts on the seat collection — can't sweep a seat).
- **Deposits** are open (`onERC721Received` accepts only the identity.md collection).
- **Exit** is `withdrawSeat`, `onlyOwner` = the Timelock → every seat exit is queued publicly >=48h ahead.
- The `WorkerAuthorization` ERC-1271 pairing is lifted verbatim from the audited IMDSeatStrategy.

## Invariants for review

- **I1.** A seat leaves ONLY via `withdrawSeat` (onlyOwner = Timelock).
- **I2.** The vault never approves a seat to anyone (no approve / setApprovalForAll).
- **I3.** `seatOperator`'s only powers are authorizeWorker / revokeWorkerAuthorization / registerAgent.
- **I4.** `isValidSignature` returns VALID only for digests inserted by `authorizeWorker` — never an arbitrary hash. A compromised operator must not be able to make the vault "sign" a sale / Seaport order.
- **I5.** `sweepEarnings` can never move a seat (ERC-20 only, fixed destination, reverts on the collection).
- **I6.** Config + exit are all onlyOwner (delayed + public).
- **I7.** Non-upgradeable: no proxy, no delegatecall, no selfdestruct.
