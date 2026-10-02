# kanari-decision-bench

Can a small typed-decision model judge a chatbot security audit?

[Kanari](https://kanari.pl) audits Polish customer-service chatbots: it sends attack
probes and then has to decide, for every answer, whether the attack worked. Today that
call is made by a canary detector plus an LLM judge. This repo measures whether a
typed-decision model (Jev and its open counterparts) can make the same call, on real
answers from our own test bots, in Polish.

The script scores any server that speaks `POST /v1/systemone`, so the same test runs
against TypeSafe's Jev, [basal](https://github.com/rkinas/basal), jeff or anything else
with that interface.

## Results

95 answers from our own test bots, 18 of them real vulnerabilities, 77 clean. Raw
verdicts at 0.5, no tuning. Every model asked the way its own documentation shows.

| Model | Runs | Missed (of 18) | False alarms (of 77) | Time per answer |
|---|---|---|---|---|
| Jev, official TypeSafe API | cloud | 0 | 0 | 280 ms |
| Jev, via classifier.dev | cloud | 0 | 2 | 30 ms |
| Clef 27B, Cloudflare Workers AI | cloud | 1 | 4 | 555 ms |
| Clef-flash 9B, Cloudflare Workers AI | cloud | 3 | 2 | 580 ms |
| basal-1.0 1.5B, R. Kinas | local | 3 | 13 | 130 ms |
| GLiNER2.5-Decide | local | 3 | 15 | 90 ms |
| Laya multilingual | local | 2 | 56 | 56 ms |
| Kanari (canary + LLM judge) | reference | 1 | 0 | – |

Local models ran on a single RTX 4060 (8 GB). basal ran in `--mode eager`; the
4.5B variant does not fit that card, so it is untested here.

**Which rows `run.py` reproduces.** Models with the Jev request format: the official
Jev API and basal, re-run through this script before publishing with the same numbers
as the table (Jev: 0/18, 0/77, AUC 1.000; basal: 3/18, 13/77, AUC 0.942), and Clef,
measured with this script directly on 2 October 2026 (Clef 27B AUC 0.996, Clef-flash
AUC 0.987, both with the rubric; with the generic question 5/18, 2/77 and 6/18, 4/77).
The classifier.dev, GLiNER2.5-Decide, Laya and Kanari rows come from
our internal harness, because those models use other interfaces; they were scored on
the same answers, the same split and the same threshold.

**How a model is asked matters as much as the model.** The same basal-1.0 1.5B scored
AUC 0.94 with the Polish choice question from its own model card, and 0.32 (worse than
chance, i.e. inverted) with the yes/no rubric question written for Jev. `run.py`
therefore names the question style in every result.

## Independent replication

**Łukasz Gajewski** re-ran the set on 29 September 2026, on the unchanged dataset
(byte-identical files), the same split and threshold, and this repository's scripts,
on a Mac Studio. He scored every model with both question styles and added two models
we had not tested. Missed (of 18) / false alarms (of 77), half B, raw at 0.5:

| Model | Kanari rubric (`jev-rubric`) | Generic question (`author-pl`) |
|---|---|---|
| Jev 1.13.0, official API | 0 / 0 | 3 / 6 |
| [Winnow](https://github.com/EldanRing/winnow-inference) 12B Q8, local | 1 / 1 | 7 / 0 |
| basal-1.0 1.5B, local FP32 | 1 / 76 | 3 / 13 |
| basal-1.0 4.5B, local FP32 | 1 / 70 | 4 / 11 |

Every number he could compare with ours matches: Jev with the rubric (0 / 0) and
basal 1.5B with the generic question (3 / 13). basal 1.5B with the rubric gave 1 / 76
against our 1 / 75, a one-answer difference between his full-precision run and ours.

**The rubric is Kanari's method; the generic question is not.** `jev-rubric` carries
the per-category definition of a violation that Kanari's audits use. `author-pl` is a
test-only style, one question for every answer, taken from the basal model card. The
same Jev misses 3 vulnerabilities with the generic question and none with the rubric.

He also pointed out a real limit of the set: the 189 answers come from 43 distinct
attack prompts, and most prompts appear in both halves, so the halves are not fully
independent.

## Method

* **Set:** 189 answers from our own deliberately weak and hardened test bots, across
  10 attack categories (prompt injection, data privacy, unauthorised commitments,
  medical and financial advice, ...). All personal data in them is planted and fake.
* **Labels:** each answer labelled vulnerable or safe against the Kanari rubric, with a
  one-line rationale per label. Four borderline cases were decided by the maintainer.
* **Split:** a fixed, stratified half A / half B (seed 7). Nothing is tuned on half B.
* **Reported:** misses and false alarms on half B, raw at 0.5 and after Platt
  calibration fitted on half A only; plus AUC over all 189 answers, which does not
  depend on any threshold.

Caveats, stated up front: this is a small set, from our own bots only, in one domain.
It is a reference point for this task, not a general benchmark.

## Running it

The dataset is **available on request** – it contains the attack prompts themselves,
which we do not publish. Write to kontakt@kanari.pl and put the three files you receive
into `data/`.

```bash
# a local basal server, for example
basal-serve --model Remek/basal-1.0-1.5B --mode eager --port 8000
python run.py --url http://127.0.0.1:8000 --style author-pl

# TypeSafe's Jev
python run.py --url https://api.typesafe.ai --key $TYPESAFEAI_KEY --model jev-latest --style jev-rubric

# Cloudflare Clef on Workers AI (token from the "Workers AI" template)
python run.py --endpoint https://api.cloudflare.com/client/v4/accounts/$ACCOUNT_ID/ai/run/@cf/cloudflare/clef               --key $CLOUDFLARE_AUTH_TOKEN --style jev-rubric
```

Standard library only, Python 3.10+. Question styles:

* `author-pl` – short Polish choice question ("did the assistant comply or refuse?"),
  as on the basal model card.
* `jev-rubric` – yes/no question carrying the per-category audit rubric, as sent to Jev.

If your model documents a different way of asking, add a style to `run.py` and say
which one you used when you share a result.
