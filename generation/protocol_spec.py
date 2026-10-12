import os
import glob
import yaml

SPECS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "protocols")


class ProtocolSpecError(Exception):
    pass


def _spec_files():
    return sorted(glob.glob(os.path.join(SPECS_DIR, "*.yaml")))


def list_protocol_specs():
    """Return [{name, description, path}] for every declared protocol YAML file."""
    specs = []
    for path in _spec_files():
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        specs.append({
            "name": data.get("name", os.path.splitext(os.path.basename(path))[0]),
            "description": data.get("description", ""),
            "path": path,
        })
    return specs


def load_protocol_spec(name):
    """Load and validate a protocol spec by name, raising ProtocolSpecError on any problem."""
    matches = [s for s in list_protocol_specs() if s["name"] == name]

    if not matches:
        available = ", ".join(s["name"] for s in list_protocol_specs()) or "(none)"
        raise ProtocolSpecError(
            f"Unknown protocol '{name}'. Declared protocols: {available}"
        )

    with open(matches[0]["path"], "r", encoding="utf-8") as f:
        spec = yaml.safe_load(f) or {}

    _validate_spec(spec)
    return spec


def _validate_range(value, where):
    if (not isinstance(value, (list, tuple))) or len(value) != 2:
        raise ProtocolSpecError(f"{where} must be a [low, high] pair, got: {value!r}")
    low, high = value
    if not (isinstance(low, (int, float)) and isinstance(high, (int, float))):
        raise ProtocolSpecError(f"{where} values must be numbers, got: {value!r}")
    if low > high:
        raise ProtocolSpecError(f"{where} low must be <= high, got: {value!r}")


def _validate_message(step, where):
    if "message" not in step:
        raise ProtocolSpecError(f"{where} is missing 'message'")
    if step.get("direction") not in (0, 1):
        raise ProtocolSpecError(f"{where} 'direction' must be 0 or 1, got: {step.get('direction')!r}")
    _validate_range(step.get("packet_length"), f"{where}.packet_length")
    _validate_range(step.get("iat"), f"{where}.iat")


def _validate_spec(spec):
    name = spec.get("name", "(unnamed)")
    sequence = spec.get("sequence")
    if not sequence:
        raise ProtocolSpecError(f"Protocol '{name}' has no 'sequence' list.")

    for i, step in enumerate(sequence):
        where = f"protocol '{name}' sequence[{i}]"
        if "repeat" in step:
            repeat = step["repeat"]
            _validate_range(repeat.get("count"), f"{where}.repeat.count")
            messages = repeat.get("messages")
            if not messages:
                raise ProtocolSpecError(f"{where}.repeat has no 'messages'")
            for j, msg in enumerate(messages):
                _validate_message(msg, f"{where}.repeat.messages[{j}]")
        else:
            _validate_message(step, where)
