# Cost model

A parameterized model that turns the savings thesis ([`VISION.md`](VISION.md#where-the-money-is))
into numbers. The lever is **reuse**: verification done once becomes an artifact presented many
times, so per-application re-verification spend collapses.

> Illustrative defaults below; plug in your own. This is a back-of-envelope model, not an audited
> financial projection.

## Parameters

| Symbol | Meaning | Example |
|---|---|---|
| `N` | hires per year | varies |
| `C` | verification checks per hire (employment, education, background, etc.) | 3 |
| `f` | average fee per check (screening + clearinghouse) | $45 |
| `H` | HR/recruiter hours per verification (chasing, phone tag, data entry) | 1.5 h |
| `w` | loaded hourly cost of that labor | $40/h |
| `r` | **reuse rate** — fraction of checks the candidate already carries as a valid claim | 0.6 |
| `b` | baseline bad-hire rate | 4% |
| `Δb` | reduction in bad-hire rate from stronger, fraud-resistant verification | 1 pt |
| `L` | average loss per bad hire (ramp, severance, backfill, lost productivity) | $15,000 |

## Formulas

Per-hire verification cost **today** (no reuse):

```
cost_today = C · (f + H · w)
```

With aion-trust, the reused fraction `r` of checks costs nothing to re-verify (a sub-second
offline check), so only `(1 − r)` of checks incur fee + labor:

```
cost_aion = C · (1 − r) · (f + H · w)
```

**Annual savings** = avoided re-verification + avoided bad hires:

```
savings = N · C · r · (f + H · w)   +   N · Δb · L
            └─ reuse savings ─┘          └─ fraud savings ─┘
```

With the example unit values, `f + H·w = 45 + 1.5·40 = $105` per check, and `C·(f+H·w) = $315`
of verification cost per hire (of which `r` is reusable).

## Worked examples (example defaults: C=3, f=$45, H=1.5h, w=$40, r=0.6, Δb=1pt, L=$15,000)

| Scenario | `N` | Reuse savings `N·C·r·(f+H·w)` | Fraud savings `N·Δb·L` | **Annual total** |
|---|---:|---:|---:|---:|
| SMB | 50 | 50·3·0.6·105 = **$9,450** | 50·0.01·15,000 = **$7,500** | **$16,950** |
| Mid-market | 500 | **$94,500** | **$75,000** | **$169,500** |
| Enterprise | 5,000 | **$945,000** | **$750,000** | **$1,695,000** |

Per hire, that's ≈ **$339 saved** ($189 reuse + $150 fraud) at these defaults.

## Sensitivity to the reuse rate `r` (Mid-market, N=500)

| `r` | Reuse savings | + Fraud savings | Annual total |
|---:|---:|---:|---:|
| 0.3 | $47,250 | $75,000 | $122,250 |
| 0.6 | $94,500 | $75,000 | $169,500 |
| 0.9 | $141,750 | $75,000 | $216,750 |

Reuse savings scale linearly with `r` — the network effect: the more issuers attest at the source
and the more candidates carry portable claims, the higher `r` climbs across the market. Fraud
savings are independent of `r` (they come from artifacts being unforgeable, not from reuse).

## What the model omits

- One-time integration cost (issuer onboarding, accreditation) — amortized, not modeled here.
- Time-to-hire value (pulling start dates forward) — real but org-specific; add `N · days_saved ·
  daily_value` if you can estimate it.
- The candidate-side savings (no repeated check fees, no waiting) — a market-adoption driver, not
  an employer line item.
