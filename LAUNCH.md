# Launch copy

Ready-to-paste announcement posts for PreCheck Guardian. Facts match the repo
(v0.2.0): 75 risk rules, approve/reject/edit, audit log, LangChain integration,
`precheck check` linter, MIT, `pip install precheck-guardian`.

Honest framing throughout: the risk scoring is a rule-based heuristic to put a
human in front of destructive actions — **not** a sandbox.

---

## Hacker News — Show HN

**Title**

```
Show HN: PreCheck Guardian – a pre-execution approval gate for AI agents
```

**Body**

```
Hi HN, I'm a 20-year-old dev and this is my project.

Autonomous agents act fast and don't ask. One `rm -rf`, one `DROP TABLE`,
one `curl | sh`, and the damage is already done. I wanted a checkpoint that
sits between an agent *planning* and *executing*: show the full plan, flag the
dangerous steps, and let a human approve / reject / edit before anything runs.

So I built PreCheck Guardian:
- Parses an agent's plan (free text, structured tool calls, or native
  OpenAI/LangChain tool-call traces) into typed steps.
- Scores each step with 75 rule-based detectors (rm -rf, DROP/TRUNCATE,
  chmod 777, curl|sh, force-push, terraform destroy, pip/npm installs, etc.).
- Prompts a human (inline, or a full-screen Textual TUI), writes a JSON-Lines
  audit log (with secret redaction), and can hard-block CRITICAL steps.
- One call, framework-agnostic, zero required dependencies. There's also a
  `precheck check <file>` linter you can drop into CI / pre-commit.

  pip install precheck-guardian

Honest scope: the risk scoring is a rule-based heuristic to surface obvious
danger for a human — it's NOT a sandbox and not a guarantee that an unflagged
step is safe. The whole point is keeping a human in the loop for destructive
actions, not replacing judgment.

Repo (MIT): https://github.com/uninhibited-scholar/precheck-guardian

I'd love feedback on the risk ruleset and on where an approval gate actually
belongs in real agent stacks. What dangerous operations should it catch that
it doesn't yet?
```

---

## Reddit — r/LocalLLaMA (also r/Python, r/LangChain)

**Title**

```
I built a pre-execution approval gate for AI agents — see the plan + per-step risk before anything runs [MIT, pip-installable]
```

**Body**

```
Agents are getting more autonomous, and the gap between "here's what I'll do"
and "...and it's already done" is where the scary stuff happens.

PreCheck Guardian inserts a human-in-the-loop checkpoint between planning and
execution:

• Parses the plan — free text, structured tool calls, or raw OpenAI/LangChain
  tool_calls.
• 75 rule-based risk detectors (rm -rf, DROP TABLE, chmod 777, curl|sh,
  force-push, terraform destroy, mass UPDATE without WHERE, ...).
• Approve / reject / edit — inline prompt or a Textual TUI.
• JSON-Lines audit log (+ secret redaction), can hard-block CRITICAL steps.
• One line to wire in, framework-agnostic, zero core deps.

Wraps a LangChain tool in one call:

    from approval_hook.integrations.langchain import guard_langchain_tool
    safe = guard_langchain_tool(my_tool)   # every call now needs approval

Also ships a standalone linter for CI/pre-commit:

    precheck check deploy.sh --fail-on critical

    pip install precheck-guardian

It's rule-based, not a sandbox — a strong safety net to put a human in front of
destructive actions, not a replacement for judgment.

Repo: https://github.com/uninhibited-scholar/precheck-guardian
Would love rule suggestions / PRs.
```

> Attach an image — the rendered TUI (`assets/tui_demo.svg`) or a screenshot of
> `python -m approval_hook`. Image posts convert far better.

---

## X / Twitter (thread)

```
1/ Autonomous AI agents act fast and don't ask.

One rm -rf. One DROP TABLE. One curl | sh. Done.

So I built PreCheck Guardian: a pre-execution approval gate that shows the plan
+ per-step risk and waits for a human. 🧵

pip install precheck-guardian

2/ It parses what the agent is about to do — free text, tool calls, or raw
OpenAI/LangChain traces — and scores every step with 75 risk rules.

rm -rf, DROP TABLE, chmod 777, curl|sh, force-push, terraform destroy... all
flagged before they run.

3/ Then a human decides: approve / reject / edit.
Inline prompt, or a full-screen TUI.

Every decision goes to a JSON-Lines audit log (secrets redacted). CRITICAL
steps can be hard-blocked entirely.

4/ Framework-agnostic, ONE call, zero required deps.

Wrap a LangChain tool:
  safe = guard_langchain_tool(my_tool)

Or lint a script in CI / pre-commit:
  precheck check deploy.sh --fail-on critical

5/ It's a rule-based safety net to keep a human in front of destructive actions
— not a sandbox.

MIT, Python 3.8+. Feedback + rule PRs very welcome 🙏
https://github.com/uninhibited-scholar/precheck-guardian
```

---

## LinkedIn

```
Shipped an open-source project: PreCheck Guardian — a pre-execution approval
gate for AI agents.

As agents get more autonomous, destructive actions (rm -rf, DROP TABLE,
curl | sh) can run before anyone reviews them. PreCheck Guardian adds a
human-in-the-loop checkpoint: it parses the agent's plan, scores each step with
75 risk rules, and lets a human approve / reject / edit — with a full audit log.

Framework-agnostic, one call to integrate, zero core dependencies. Also works
as a standalone CI / pre-commit linter.

MIT licensed, pip-installable:
https://github.com/uninhibited-scholar/precheck-guardian

Feedback and contributions welcome.
```

---

## Timing & tactics

1. **Show HN first** — Tue/Wed, ~8–10am PT. Don't upvote-beg; the first 1–2
   hours of organic engagement decide ranking. Reply to every comment.
2. Right after, cross-post to **r/LocalLLaMA** (with an image) and the **X thread**.
3. **LinkedIn** any time — good for the portfolio / hiring angle.
4. Every post should **ask for feedback** ("what dangerous ops should it catch?")
   — turning readers into contributors is the fastest path to stars.
