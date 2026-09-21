# Provider test costs

MendPact's default development loop does not need paid model calls. Run mocked driver tests and
saved replays on every commit, then use a small live-provider sample only when validating a model
integration or preparing a release. The unified guard uses deterministic replay data and also
costs $0 in provider usage. Comparing saved model reports with `mendpact compare-models` is also
offline and free. Selected tools are graded but never executed.

## Recommended test ladder

| Stage | Frequency | Live calls | Approximate cost |
| --- | --- | ---: | ---: |
| Unit tests and replay | Every commit and pull request | 0 | $0 |
| Provider smoke test | Weekly or after driver changes | 10 trials per provider | About $0.02 total |
| Release matrix | Before a release | 100 scenarios × 3 repetitions per provider | About $0.67 total |

These estimates assume roughly 800 ordinary input tokens and 50 output tokens per trial. The
Anthropic estimate also includes approximately 588 provider-added input tokens for required tool
selection. Actual cost changes with catalog size, descriptions, schemas, prompts, cached input,
and provider pricing.

| Example low-cost model | Estimated cost per trial | 300-trial release run |
| --- | ---: | ---: |
| OpenAI GPT-5.6 Luna | $0.00022 | $0.066 |
| Gemini 3.5 Flash-Lite | $0.00040 | $0.12 |
| Claude Haiku 4.5 | $0.00160 | $0.48 |

Together, the three 300-trial runs are approximately $0.67. Batch APIs can reduce eligible
asynchronous evaluation costs by roughly 50%. Gemini may offer a free tier, but its data-use
terms differ from paid service; use synthetic scenarios and review the current terms before
sending project data.

## Cost controls

- Keep deterministic replays and mocked API responses in CI.
- Run live calls only in a protected, manually triggered job with a small scenario cap.
- Keep the Action's `max-trials` limit at 10 for smoke tests; raising it must be a reviewed change.
- Start with one inexpensive model before running the same suite across every provider.
- Record token counts in behavior reports and stop a run when its configured budget is reached.
- For a hosted product, use bring-your-own-key accounts so provider usage belongs to the user.
- Recheck provider prices before setting a production budget.

Pricing references: [OpenAI GPT-5.6 Luna](https://developers.openai.com/api/docs/models/gpt-5.6-luna),
[Gemini API pricing](https://ai.google.dev/gemini-api/docs/pricing), and
[Anthropic pricing](https://platform.claude.com/docs/en/about-claude/pricing).
