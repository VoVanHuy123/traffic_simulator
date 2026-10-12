import os
import glob
import yaml

from rules.protocol_rules import PROTOCOL_RULES

SCENARIOS_DIR = os.path.dirname(__file__)


class ScenarioError(Exception):
    pass


def _scenario_files():
    return sorted(glob.glob(os.path.join(SCENARIOS_DIR, "*.yaml")))


def list_scenarios():
    """Return [{name, description, path}] for every scenario YAML file."""
    scenarios = []
    for path in _scenario_files():
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        scenarios.append({
            "name": data.get("name", os.path.splitext(os.path.basename(path))[0]),
            "description": data.get("description", ""),
            "path": path,
        })
    return scenarios


def load_scenario(name):
    """Load and validate a scenario by name, raising ScenarioError on any problem."""
    matches = [s for s in list_scenarios() if s["name"] == name]

    if not matches:
        available = ", ".join(s["name"] for s in list_scenarios()) or "(none)"
        raise ScenarioError(
            f"Unknown scenario '{name}'. Available scenarios: {available}"
        )

    with open(matches[0]["path"], "r", encoding="utf-8") as f:
        scenario = yaml.safe_load(f) or {}

    _validate_scenario(scenario)
    return scenario


def _validate_scenario(scenario):
    if not scenario.get("components"):
        raise ScenarioError(
            f"Scenario '{scenario.get('name')}' has no 'components' list."
        )

    if not scenario.get("output"):
        raise ScenarioError(
            f"Scenario '{scenario.get('name')}' is missing an 'output' path."
        )

    for comp in scenario["components"]:
        protocol = comp.get("protocol")
        if not protocol:
            raise ScenarioError("Every scenario component needs a 'protocol' field.")

        if protocol not in PROTOCOL_RULES:
            available = ", ".join(sorted(PROTOCOL_RULES.keys()))
            raise ScenarioError(
                f"Unknown protocol '{protocol}' in scenario '{scenario.get('name')}'. "
                f"Known protocols: {available}"
            )

        from generation import GenRegistry
        if GenRegistry.get_generator_handler(protocol) is None:
            raise ScenarioError(
                f"Protocol '{protocol}' has no registered generator "
                f"(check generation/__init__.py)."
            )

        num_flows = comp.get("num_flows")
        if not isinstance(num_flows, int) or num_flows <= 0:
            raise ScenarioError(
                f"Component '{protocol}' in scenario '{scenario.get('name')}' needs a "
                f"positive integer 'num_flows'."
            )
