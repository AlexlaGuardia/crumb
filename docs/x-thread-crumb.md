# X thread: Crumb overview (article #7)
> Staged 2026-07-18, ending upgraded 2026-07-25 (pip install + live verify + Rekor-catches-forgery milestone).
> Pride-gated. Self-contained (whole story, no tease). Link in LAST post only.
> Alex posts (X flags automation signature, not volume). Paste per feedback_x_composer_paste.
> Writeup: https://alexlaguardia.dev/writing/crumb | demo: https://crumb.alexlaguardia.dev

1/ an agent exported a patient record. it ran under a shared service account, so the audit log says the bot did it.. it never says which person told it to.

2/ eu ai act article 12 kicks in aug 2 2026. high-risk systems need logs that identify the actual person involved.. not a service account, not an agent id. shared creds can't answer that, the identity was never captured.

3/ obvious fix: make the model report who it's acting for. two problems.. a tool call has no field for who, and anything the model emits is prompt-injectable. tested it: the tool description hijacked more models than the tool output did.

4/ so i built crumb. one gateway, every tool call passes through it.. pulls the human's identity from the verified session, never the model, mints an rfc 8693 token, human as sub, agent as act. writes it to a hash-chained ledger before the tool ever runs.

5/ multi-hop works too. alice authorizes read_record, a planner delegates to a researcher sub-agent.. crumb traces it back to alice, verified. a rogue hop calls export_record instead, which alice never touched.. crumb clears her by name and points at the agent chain that did it.

6/ the scary part: i hold the signing key. i could rewrite a crumb, re-sign the whole chain, and per-entry verify would still pass.. so the ledger checkpoints its merkle root to sigstore's public rekor log. rewrite history and the root stops matching what's already public.

7/ what it isn't: crumb doesn't stop actions, cerbos/capsule/astrix do that already. cross-issuer delegation still rests on a federation trust set i made explicit, not solved away.

8/ crumb's on pypi now.. `pip install crumb-attest`, real package, no version pin needed. point `crumb verify` at the live demo ledger and it checks the chain and signatures first.. then pulls sigstore's rekor entry live and compares it. green in about a second.

9/ did it for real today.. clicked rollback on the demo. it rewrote a crumb and re-signed the whole chain with the key i hold. chain still checks out, internally consistent. merkle doesn't match rekor though, so verify catches it. reload and it heals itself back.

10/ ~30 seconds, on your own machine.. install it, verify clean. then break it on the demo and watch crumb catch it, not me telling you it works.

pip install crumb-attest
crumb verify https://crumb.alexlaguardia.dev

longer version: https://alexlaguardia.dev/writing/crumb
