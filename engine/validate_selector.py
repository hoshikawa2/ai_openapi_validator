import json
import sys
import os
import re
from jsonpath_ng import parse
from jsonpath_ng.jsonpath import DatumInContext, Fields
from ruamel.yaml import YAML

# Regex for $.root['key']<suffix>
_BRACKET_RE = re.compile(r"^\$\.(\w+)\['([^']+)'\](.*)$")

def load_spec(path: str):
    _, ext = os.path.splitext(path)
    with open(path, "r", encoding="utf-8") as f:
        if ext.lower() in [".yaml", ".yml"]:
            yaml = YAML(typ="safe")
            return yaml.load(f)
        return json.load(f)

def load_rules(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def find_with_selector(selector: str, spec: dict):
    m = _BRACKET_RE.match(selector)
    if not m:
        expr = parse(selector)
        return expr.find(spec)

    root_prop, key, suffix = m.group(1), m.group(2), m.group(3)

    if root_prop not in spec or not isinstance(spec[root_prop], dict):
        return []

    root_ctx = DatumInContext.wrap(spec)
    prop_ctx = DatumInContext(value=spec[root_prop], path=Fields(root_prop), context=root_ctx)

    if key not in spec[root_prop]:
        return []

    key_ctx = DatumInContext(value=spec[root_prop][key], path=Fields(key), context=prop_ctx)

    if not suffix:
        return [key_ctx]

    expr = parse(f"${suffix}")
    sub_matches = expr.find(key_ctx.value)

    return [DatumInContext(value=sm.value, path=sm.path, context=key_ctx) for sm in sub_matches]

def validate_selectors(spec_path: str, rules_path: str, only_errors: bool = False):
    spec = load_spec(spec_path)
    rules = load_rules(rules_path)

    results = []
    for rule in rules:
        selector = rule.get("selector")
        rule_code = rule.get("rule_code", "NO_CODE")
        try:
            matches = find_with_selector(selector, spec)
            results.append({
                "rule_code": rule_code,
                "selector": selector,
                "status": "OK",
                "matches_count": len(matches)
            })
        except Exception as e:
            results.append({
                "rule_code": rule_code,
                "selector": selector,
                "status": "ERRO",
                "error": str(e)
            })
    return [r for r in results if r["status"] == "ERRO"] if only_errors else results

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python validate_selectors.py <spec.json|yaml> <rules.json> [--only-errors]")
        sys.exit(1)

    spec_path, rules_path = sys.argv[1], sys.argv[2]
    only_errors = "--only-errors" in sys.argv

    results = validate_selectors(spec_path, rules_path, only_errors)

    print("\n=== VALIDATION RESULT ===")
    if not results:
        print("No errors found." if only_errors else "Everything validated successfully.")
    else:
        for r in results:
            if r["status"] == "OK":
                print(f"[{r['rule_code']}] {r['selector']} → ✅ ({r['matches_count']} matches)")
            else:
                print(f"[{r['rule_code']}] {r['selector']} → ❌ {r['error']}")
