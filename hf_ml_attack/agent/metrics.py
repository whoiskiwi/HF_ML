import json
import time
import os
from datetime import datetime


class Metrics:
    def __init__(self):
        self.start_time = time.time()
        self.total_steps = 0
        self.llm_calls = 0
        self.actions_taken = []
        self.time_per_step = []
        self.success = False
        self.fail_reason = None
        self._step_start = None

    def step_start(self):
        self._step_start = time.time()
        self.total_steps += 1
        self.llm_calls += 1

    def step_end(self, actions: list[str]):
        elapsed = round(time.time() - self._step_start, 2)
        self.time_per_step.append(elapsed)
        self.actions_taken.extend(actions)

    def finish(self, success: bool, reason: str = None):
        self.success = success
        self.fail_reason = reason

    def save(self):
        os.makedirs("results", exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        data = {
            "timestamp": timestamp,
            "total_steps": self.total_steps,
            "llm_calls": self.llm_calls,
            "total_time_seconds": round(time.time() - self.start_time, 2),
            "time_per_step": self.time_per_step,
            "actions_taken": self.actions_taken,
            "success": self.success,
            "fail_reason": self.fail_reason
        }
        path = f"results/run_{timestamp}.json"
        with open(path, "w") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        print(f"\n[Metrics] Saved to {path}")
        return data
