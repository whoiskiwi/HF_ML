from state import AttackState
from executor import dispatch_all_queued_tasks, AGENT_NAMESPACE
from planner import build_env_prompt, parse_response, call_llm, SYSTEM_PROMPT
from metrics import Metrics

MAX_STEPS = 40


def run():
    print("=" * 60)
    print("HuggingFace Breach — Autonomous AI Attack Agent")
    print("Planner: Claude Haiku 4.5")
    print("=" * 60)

    state   = AttackState()
    metrics = Metrics()

    messages = [{"role": "system", "content": SYSTEM_PROMPT}]
    last_results: list[dict] = []

    for step in range(1, MAX_STEPS + 1):
        print(f"\n{'─' * 50}")
        print(f"Step {step}")

        env_prompt = build_env_prompt(state, last_results)
        messages.append({"role": "user", "content": env_prompt})

        metrics.step_start()
        raw = call_llm(messages)
        messages.append({"role": "assistant", "content": raw})

        think, action_code, finished = parse_response(raw)

        if think:
            print(f"\n[Thinking]\n{think}")

        if finished:
            print(f"\n[Done]\n{finished}")
            metrics.finish(success=True)
            metrics.step_end([])
            break

        if not action_code:
            print("[Warning] No <action> returned, skipping step")
            metrics.step_end([])
            last_results = [{"status": "SKIP", "action": "none", "note": "No action returned"}]
            continue

        print(f"\n[Action]\n{action_code}")

        try:
            exec(action_code, {**AGENT_NAMESPACE})
        except Exception as e:
            print(f"[Error] exec failed: {e}")
            last_results = [{"status": "FAILED", "action": "exec", "error": str(e)}]
            metrics.step_end(["exec_error"])
            continue

        last_results = dispatch_all_queued_tasks(state)

        print("\n[Results]")
        actions_this_step = []
        for r in last_results:
            status = r.get("status", "?")
            action = r.get("action", "?")
            print(f"  [{status}] {action}", end="")
            if "output" in r:
                print(f": {r['output'][:150]}")
            elif "data" in r:
                print(f": {r['data'][:150]}")
            elif "note" in r:
                print(f": {r['note']}")
            elif "error" in r:
                print(f": error - {r['error']}")
            else:
                print()
            actions_this_step.append(action)

        metrics.step_end(actions_this_step)

    else:
        metrics.finish(success=False, reason=f"Exceeded max steps ({MAX_STEPS})")
        print(f"\n[Stopped] Exceeded max steps: {MAX_STEPS}")

    data = metrics.save()
    print(f"\nSteps: {data['total_steps']} | Time: {data['total_time_seconds']}s | Success: {data['success']}")


if __name__ == "__main__":
    run()
