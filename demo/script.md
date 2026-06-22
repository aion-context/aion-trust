# aion-trust — demo voice script (DRAFT)

**One idea:** *A résumé you can prove — do the work once, prove it forever.*
**Audience:** buyers / decision-makers (CTO, head of talent, head of security).
**Covers:** full product tour (issuer · wallet · verifier) + the revoke→reject moment + W3C interop.
**Runtime:** ~2:55 · **Status:** produced → `demo/aion-trust-demo.mp4`.
**Voice (ElevenLabs):** *Sarah — Mature, Reassuring, Confident* (`EXAVITQu4vr4xnSDxMaL`),
model **`eleven_v3`** (latest); API key in `~/.creds/eleven.env`.
**Pronunciation:** the spoken text respells a few tokens (the on-screen script below is unchanged):
`aion → "eye-on"`, `W3C → "W three C"`, `did:key → "did key"`, `PDF → "P D F"`.

> Numbers/IDs are never read aloud — hashes and DIDs stay on screen. The voice carries the meaning;
> the screen carries the proof.

---

## Storyboard

| # | Screen / on-screen action | Voiceover | ~sec |
|---|---|---|---|
| 1 | **Home** hero. Slow settle on "A résumé you can prove." | A résumé is a claim anyone can type. Today an employer has to prove it by hand — calling past employers, re-running background checks, chasing transcripts. It's slow, it's paid for again on every application, and it's routinely faked. aion-trust replaces the claim with proof: every fact is attested once, at its source, signed by the party that can actually vouch for it — and from then on, anyone can verify it offline, in seconds. | 24 |
| 2 | **Home** — cursor passes over the three rooms: Issuer, Candidate, Employer. | There are three parties, and three rooms. The issuer attests a fact. The candidate holds it. The employer verifies it. No one in the middle — and no central database of people. | 12 |
| 3 | **/issuer** — fill the employment form, click Issue; the claim appears in the table; hover the "accredited" badge. | In the issuer console, an accredited employer signs an employment record — title, dates, rehire eligibility — and hands the signed claim to the candidate. Issuers are accredited on a shared registry, so a verifier can later tell an authoritative attestation from a merely self-asserted one. And here is what matters for privacy: that shared registry holds only keys, accreditation, and an opaque status. No personal data ever touches it. | 27 |
| 4 | **/wallet** — show the held claims; build a presentation choosing a subset of fields. | The claim lives in the candidate's wallet — on their device, theirs to keep. When they apply, they don't hand over everything. They build a presentation: a minimized, audience-bound bundle that reveals only the fields this employer needs — the job title, but not the salary; that a degree is at least a bachelor's, without the transcript. It's single-use, and it expires. | 24 |
| 5 | **/verify** — show the pending presentation, click Verify; the four checks tick green; the ACCEPTED verdict lands. | The employer verifies it offline, against the registry — no portal, no phone call. Four checks, every time: the presentation is bound to this employer; each claim's signature is authentic; the issuer was accredited; and the claim has not been revoked. All four pass. Accepted. | 22 |
| 6 | **/walkthrough** — let it run; pause on act 4 (green ACCEPTED), then act 5 (amber Revoked), then act 6 (red REJECTED). | Now watch revocation. The issuer withdraws the claim on the registry. Nothing about the person changes — only the claim's standing. The candidate presents the very same credential again, and now it fails. Red. "Claim not revoked" is the check that flips. That is the difference between a PDF and a proof. | 23 |
| 7 | **Terminal** — run `export-vp` → show the W3C VC JSON; run `import-vp` → "verified"; tamper a field → rejected; swap the key → binding rejected. | And it travels. A presentation exports as a standard W3C Verifiable Credential, with the issuer's key as a did:key — so it parses in any compliant tool. We keep our own signature inside it, so the proof survives the round trip. Tamper with one disclosed field, and import rejects it. Swap the signing key, and the binding check rejects it. The guarantees come with the artifact, wherever it goes. | 26 |
| 8 | **Home** — settle back on the hero; the motto in the footer. | That's the model: verification done once and reused across every application — at zero marginal cost, with fraud designed out. Do the work once. Prove it forever. | 14 |

**Running total:** ~2:52.

---

## Pure narration (lift into `demo/narration.txt` for ElevenLabs)

A résumé is a claim anyone can type. Today an employer has to prove it by hand — calling past employers, re-running background checks, chasing transcripts. It's slow, it's paid for again on every application, and it's routinely faked. aion-trust replaces the claim with proof: every fact is attested once, at its source, signed by the party that can actually vouch for it — and from then on, anyone can verify it offline, in seconds.

There are three parties, and three rooms. The issuer attests a fact. The candidate holds it. The employer verifies it. No one in the middle — and no central database of people.

In the issuer console, an accredited employer signs an employment record — title, dates, rehire eligibility — and hands the signed claim to the candidate. Issuers are accredited on a shared registry, so a verifier can later tell an authoritative attestation from a merely self-asserted one. And here is what matters for privacy: that shared registry holds only keys, accreditation, and an opaque status. No personal data ever touches it.

The claim lives in the candidate's wallet — on their device, theirs to keep. When they apply, they don't hand over everything. They build a presentation: a minimized, audience-bound bundle that reveals only the fields this employer needs — the job title, but not the salary; that a degree is at least a bachelor's, without the transcript. It's single-use, and it expires.

The employer verifies it offline, against the registry — no portal, no phone call. Four checks, every time: the presentation is bound to this employer; each claim's signature is authentic; the issuer was accredited; and the claim has not been revoked. All four pass. Accepted.

Now watch revocation. The issuer withdraws the claim on the registry. Nothing about the person changes — only the claim's standing. The candidate presents the very same credential again, and now it fails. Red. "Claim not revoked" is the check that flips. That is the difference between a PDF and a proof.

And it travels. A presentation exports as a standard W3C Verifiable Credential, with the issuer's key as a did:key — so it parses in any compliant tool. We keep our own signature inside it, so the proof survives the round trip. Tamper with one disclosed field, and import rejects it. Swap the signing key, and the binding check rejects it. The guarantees come with the artifact, wherever it goes.

That's the model: verification done once and reused across every application — at zero marginal cost, with fraud designed out. Do the work once. Prove it forever.

---

## Production notes (for the "act it out" phase)

Mirrors the `completeness-engine-pr12/demo` pipeline:

1. **Narration** → ElevenLabs (`~/.creds/eleven.env`, recommended voice above) → `demo/narration.mp3`.
2. **Screen** → Playwright drives `http://127.0.0.1:8080` for scenes 1–6 and a terminal pane for
   scene 7 (the interop CLI), recording to `demo/aion-trust-demo-raw.webm`. Scene durations above
   set the per-step waits so the action lands on the narration.
3. **Mux** → ffmpeg combines webm + mp3 → `demo/aion-trust-demo.mp4`; capture a thumbnail.
4. **Manifest** → `demo/DEMO-MANIFEST.md` listing every artifact + final ffprobe, as in the precedent.

Open question before recording: lock the **voice** choice, and confirm **timings** (tighten to ~2:00
or keep ~2:45). Audio + recording are a paid external step — run only on your go.
