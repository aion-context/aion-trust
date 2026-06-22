# aion-trust demo artifact

Created: 2026-06-22
Surfaces recorded: `http://127.0.0.1:8080` (issuer · wallet · verifier · walkthrough) +
`http://127.0.0.1:8091/interop.html` (W3C interop scene).

## Final artifact

`demo/aion-trust-demo.mp4` — narrated product tour + interop, ~2:47.

## Source artifacts

| Artifact | Path |
|---|---|
| Voice script / storyboard | `demo/script.md` |
| Per-scene narration text | `demo/narration/scene-1..8.txt` |
| Per-scene narration audio (ElevenLabs) | `demo/narration/scene-1..8.mp3` |
| Concatenated narration | `demo/narration.mp3` |
| Scene durations (sync source) | `demo/durations.json` |
| Playwright recorder | `demo/record-demo.js` |
| Raw screen recording | `demo/playwright-video/*.webm` |
| Interop scene page | `demo/interop.html` (built from `demo/interop-vc.json`) |
| Thumbnail | `demo/demo-thumbnail.jpg` |

## Narration

- Voice: ElevenLabs **Sarah — Mature, Reassuring, Confident** (`EXAVITQu4vr4xnSDxMaL`),
  model **`eleven_v3`** (latest). Key: `~/.creds/eleven.env`.
- 8 scenes generated separately and measured, so the screen action tracks each line.
- Pronunciation respellings in the spoken text (not the on-screen script): `aion → "eye-on"`,
  `W3C → "W three C"`, `did:key → "did key"`, `PDF → "P D F"`, plus a `<break>` for pacing.

## Scenes (start → narration)

| # | t (s) | Surface | Beat |
|---|------:|---------|------|
| 1 | 0.0   | Home hero | The résumé is an unverified claim; replace it with proof |
| 2 | 28.9  | Home rooms | Three parties, three rooms, no middleman |
| 3 | 39.8  | Issuer | Accredited issuer signs a record; registry holds no PII |
| 4 | 69.0  | Wallet | Candidate-owned; minimized, audience-bound disclosure |
| 5 | 92.6  | Verify | Four checks pass offline → ACCEPTED |
| 6 | 110.0 | Walkthrough | Revoke → the same credential now fails (red) |
| 7 | 130.7 | Interop | Exports as a W3C VC (did:key); guards hold on import |
| 8 | 156.6 | Home | Verify once, reuse everywhere; the motto |

## Verification

Final MP4 (ffprobe):

- Container: MP4 (`+faststart`)
- Duration: 175.360 s
- Video: H.264, 1440×900, 25 fps
- Audio: AAC, 192 kbps
- Narration track: 175.673 s (model `eleven_v3`)

The interop scene's Verifiable Credential is real output from
`aion-trust export-vc` (saved as `demo/interop-vc.json`); the three guard outcomes
(round-trip re-verifies, tampered field rejected, swapped key rejected) are actual
`aion-trust import-vc` results.

## Reproduce

```sh
aion-trust serve --port 8080                                   # surfaces
( cd demo && python3 -m http.server 8091 )                     # interop scene
# regenerate narration: see demo/script.md (ElevenLabs)
NODE_PATH=<playwright> node demo/record-demo.js                 # record webm
ffmpeg -f concat -safe 0 -i demo/concat.txt -c copy demo/narration.mp3
ffmpeg -i demo/playwright-video/*.webm -i demo/narration.mp3 \
  -c:v libx264 -crf 20 -pix_fmt yuv420p -r 25 -c:a aac -b:a 192k \
  -shortest -movflags +faststart demo/aion-trust-demo.mp4
```
