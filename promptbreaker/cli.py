"""Command line.

  python -m promptbreaker matrix                                   # offline, mock model
  python -m promptbreaker matrix --backend ollama --model qwen2.5:7b
  python -m promptbreaker serve --defenses all_filters             # open http://127.0.0.1:5000
  python -m promptbreaker matrix --url http://127.0.0.1:5000       # attack the running server
  python -m promptbreaker adaptive --goal leak_secret --attacker-backend ollama --attacker-model qwen2.5:7b
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from .app import create_app
from .harness import CONFIGS, HttpTarget, InProcessTarget, load_attacks, matrix_table, run_adaptive, run_matrix
from .llm import make_llm
from .mock_model import NaiveModel

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "results"


def target_llm(args):
    return NaiveModel() if args.backend == "mock" else make_llm(args.backend, args.model)


def defenses_of(name: str):
    if name in CONFIGS:
        return CONFIGS[name]
    return tuple(x for x in name.split(",") if x)


def save(name: str, payload: dict, table: str = "") -> Path:
    d = RESULTS / f"{time.strftime('%Y%m%d-%H%M%S')}_{name}"
    d.mkdir(parents=True, exist_ok=True)
    (d / "results.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    if table:
        (d / "matrix.md").write_text(table + "\n", encoding="utf-8")
    return d


def cmd_matrix(args):
    attacks = load_attacks(args.attacks)
    if args.url:
        t = HttpTarget(args.url)
        results = run_matrix(lambda _d: t, attacks, {"server": ()})
    else:
        llm = target_llm(args)
        results = run_matrix(lambda d: InProcessTarget(llm, d), attacks)
    table = matrix_table(results)
    print(table)
    d = save(f"matrix_{args.backend if not args.url else 'server'}", results, table)
    print(f"\nSaved to {d}")


def cmd_serve(args):
    app = create_app(target_llm(args), defenses_of(args.defenses))
    print(f"ShopBot on http://127.0.0.1:{args.port} with defenses: {defenses_of(args.defenses) or 'none'}")
    app.run(host="127.0.0.1", port=args.port)


def cmd_adaptive(args):
    attacker = make_llm(args.attacker_backend, args.attacker_model, args.attacker_script)
    target = HttpTarget(args.url) if args.url else InProcessTarget(target_llm(args), defenses_of(args.defenses))
    res = run_adaptive(attacker, target, args.goal, args.max_attempts)
    for i, a in enumerate(res.attempts, 1):
        print(f"[{i}] {'SUCCESS' if a['success'] else 'failed '} {a['why']}: {a['reply'][:100]!r}")
    print(f"\nGoal {args.goal}: {'reached' if res.success else 'not reached'} in {len(res.attempts)} attempt(s)")
    save(f"adaptive_{args.goal}_{args.defenses.replace(',', '+')}", {"success": res.success, "attempts": res.attempts})


def main(argv=None):
    p = argparse.ArgumentParser(prog="promptbreaker", description="Automated red teaming of an LLM web app")
    sub = p.add_subparsers(dest="cmd", required=True)

    def target_opts(s):
        s.add_argument("--backend", choices=["mock", "ollama", "openai", "anthropic"], default="mock",
                       help="model behind ShopBot (mock = offline stand-in)")
        s.add_argument("--model")

    m = sub.add_parser("matrix", help="run the attack library against every defense configuration")
    target_opts(m)
    m.add_argument("--attacks", default=str(Path(__file__).with_name("attacks.yml")))
    m.add_argument("--url", help="attack a running server instead (localhost only)")
    m.set_defaults(fn=cmd_matrix)

    s = sub.add_parser("serve", help="run the ShopBot web app")
    target_opts(s)
    s.add_argument("--defenses", default="none", help=f"{'|'.join(CONFIGS)} or a comma list")
    s.add_argument("--port", type=int, default=5000)
    s.set_defaults(fn=cmd_serve)

    a = sub.add_parser("adaptive", help="an attacker LLM adapts its attack from the bot's replies")
    target_opts(a)
    a.add_argument("--defenses", default="all_filters")
    a.add_argument("--goal", choices=["leak_secret", "tool_abuse"], default="leak_secret")
    a.add_argument("--attacker-backend", choices=["ollama", "openai", "anthropic", "scripted"], default="ollama")
    a.add_argument("--attacker-model")
    a.add_argument("--attacker-script")
    a.add_argument("--max-attempts", type=int, default=8)
    a.add_argument("--url")
    a.set_defaults(fn=cmd_adaptive)

    args = p.parse_args(argv)
    args.fn(args)


if __name__ == "__main__":
    main()
