import json
import re
import sys
import fnmatch
from pathlib import Path

import ruamel.yaml
from jsonpath_ng import parse
from jsonpath_ng.jsonpath import DatumInContext, Fields
from collections import OrderedDict
from types import SimpleNamespace

from langchain_ollama import ChatOllama

# ---------------------------
# Severity
# ---------------------------
SEVERITY_LEVELS = {"info": 1, "warning": 2, "error": 3}


def severity_allowed(rule_severity, min_severity):
    return SEVERITY_LEVELS[rule_severity] >= SEVERITY_LEVELS[min_severity]

# -------------------------
# 2. Configure LLM Ollama
# -------------------------
llm = ChatOllama(
    base_url="http://127.0.0.1:11434",
    model="mistral:instruct",
    temperature=0.0,
    num_ctx=8192
)

# ---------------------------
# Loaders
# ---------------------------
def load_spec(file_path: str):
    """Loads the OpenAPI specification in JSON/YAML."""
    path = Path(file_path)
    yaml = ruamel.yaml.YAML(typ="safe")

    with open(path, "r", encoding="utf-8") as f:
        if path.suffix.lower() in [".yaml", ".yml"]:
            return yaml.load(f)
        return json.load(f, object_pairs_hook=OrderedDict)


def load_rules(file_path: str):
    """Loads rules in JSON."""
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)

# ---------------------------
# AI
# ---------------------------
def analyze_with_llm_infinitive(spec_text: str) -> list[dict]:
    """
    Parses the entire OpenAPI specification using LLM
    and returns a JSON array of update rules.
    """
    prompt = f"""
    You are a smart parser of OpenAPI/Swagger specifications.
    
    Your task:
    1. Scan all operationId fields in the OpenAPI specification below.
    2. If an operationId does not start with a verb in **Portuguese infinitive form** (e.g. "Aplicar", "Somar", "Atualizar", "Consultar", "Obter", "Listar"),
       generate a JSON update rule correcting it.
       - Examples:
         - "AplicaAgrupamentoCommandReqPost" → "AplicarAgrupamentoCommandReqPost"
         - "SomaAgrupamentoCommandReqPut" → "SomarAgrupamentoCommandReqPut"
    
    3. For each problem found, create a JSON object with:
       - rule_code: "LLMxx"
       - summary: in Portuguese
       - scope: "paths"
       - op: "update"
       - selector: JSONPath of the parent object (e.g., $.paths["/grouping/group"].post)
       - field: "operationId"
       - value: corrected operationId
       - check_text: explain the problem
       - severity: "error"
       - autofix: true
       - hints: tips in Portuguese
       - oas_version: null
    
    ⚠️ Rules:
    - Always return a JSON array (no text around it).
    - Always use absolute JSONPath starting with "$.".
    - For keys with "/" or "-", use double quotes inside brackets (e.g., $.paths["/users"]).
    - The selector must point to the parent, and field must be "operationId".
    
    Example output:
    
    [
      {{
        "rule_code": "LLM01",
        "summary": "operationId deve iniciar com verbo no infinitivo",
        "scope": "paths",
        "op": "update",
        "selector": "$.paths[\"/grouping/group\"].post",
        "field": "operationId",
        "value": "AtualizarAgrupamentoCommandReqPost",
        "check_text": "operationId precisa iniciar com verbo no infinitivo",
        "severity": "error",
        "autofix": true,
        "hints": ["Use sempre verbos no infinitivo: Criar, Somar, Atualizar, Consultar, Obter, Listar"],
        "oas_version": null
      }}
    ]
    
    Specification for analysis:
    {spec_text}
    """


    response = llm.invoke(prompt)

    raw = response.content.strip()

    if not raw:
        raise ValueError(f"LLM's empty response to rule")

    # Extrair apenas o JSON
    start = raw.find("[")
    end = raw.rfind("]") + 1
    if start == -1 or end == -1:
        return {
            "rule_code": f"R_FAIL_AI",
            "summary": "Failure to interpret",
            "scope": "OTHER",
            "op": "OTHER",
            "selector": "$",
            "field": "*",
            "check_text": "Error decoding rule",
            "severity": "error",
            "hints": ["Manually review"],
            "autofix": False,
            "oas_version": None
        }

    raw_json = raw[start:end]

    def sanitize(text: str) -> str:
        text = text.replace("'", '"')  
        text = re.sub(r",(\s*[}\]])", r"\1", text)  
        text = text.replace("\\", "\\\\")  
        text = text.replace("\nNone\n", "null")
        return text

    try:
        parsed = json.loads(raw_json)
    except json.JSONDecodeError:
        print("⚠️ Invalid JSON in rule, trying to fix...")
        safe = sanitize(raw_json)
        try:
            parsed = json.loads(safe)
        except json.JSONDecodeError as e:
            print(f"❌ Failed to fix rule JSON: {e}")
            return [{
                "rule_code": "R_FAIL_AI",
                "summary": "Failure to interpret",
                "scope": "OTHER",
                "op": "OTHER",
                "selector": "$",
                "field": "*",
                "check_text": "Error decoding rule",
                "severity": "error",
                "hints": ["Manually review"],
                "autofix": False,
                "oas_version": None
            }]

    # 🔑 Normalization: always ensure list
    if isinstance(parsed, dict):
        return [parsed]
    elif isinstance(parsed, list):
        return parsed
    else:
        return [{
            "rule_code": "R_FAIL_AI",
            "summary": "Unexpected response (not list or dict)",
            "scope": "OTHER",
            "op": "OTHER",
            "selector": "$",
            "field": "*",
            "check_text": "Error decoding rule",
            "severity": "error",
            "hints": ["Manually review"],
            "autofix": False,
            "oas_version": None
        }]

# ---------------------------
# HELPERS
# ---------------------------
def rename_key_preserve_order(d, old_key, new_key):
    new_dict = OrderedDict()
    for k, v in d.items():
        if k == old_key:
            new_dict[new_key] = v
        else:
            new_dict[k] = v
    d.clear()
    d.update(new_dict)

def fix_with_pattern(value: str, pattern: str) -> str:
    """
    Try to fix `value` so that it follows the `pattern`.
    This version infers intent from the regex itself and performs minimal fixes.

    If pattern contains a literal prefix (e.g., '^http://Caminho_backend/'),
    that prefix will be enforced. Otherwise, case-style or structural rules apply.
    """
    regex = re.compile(pattern)

    # If already OK, return unchanged
    if regex.match(value):
        return value

    # --- Case 1: the pattern has a fixed literal prefix or base string ---
    # (e.g. '^http://Caminho_backend/', '^/api/v[0-9]+', etc.)
    literal_prefix = None
    m_prefix = re.match(r'^\^([^.*+?$()[\]{}|\\]+)', pattern)
    if m_prefix:
        prefix_candidate = m_prefix.group(1)
        # detect if it looks like a URL or path
        if any(x in prefix_candidate for x in ["://", "/", "."]):
            literal_prefix = prefix_candidate

    if literal_prefix:
        # Keep the suffix of original value after the first slash
        parts = re.split(r"https?://[^/]+/", value, 1)
        if len(parts) == 2:
            suffix = parts[1]
        else:
            suffix = re.sub(r"^/*", "", value)
        fixed = literal_prefix.rstrip("/") + "/" + suffix.lstrip("/")
        fixed = re.sub(r"\.\*\$","", fixed)
        return fixed

    # --- Case 2: try to deduce intent from the pattern syntax ---
    pattern_lc = pattern.lower()
    is_url_like = "://" in pattern_lc or "/" in pattern_lc or "api" in pattern_lc
    is_snake = "_" in pattern
    is_kebab = "-" in pattern and not "_" in pattern
    is_upper = re.search(r"[A-Z]", pattern) and pattern.isupper()
    is_camel = re.search(r"[A-Z]", pattern) and not ("_" in pattern or "-" in pattern)

    # URL/path-like → don't destroy structure
    if is_url_like:
        return value  # leave untouched; validator will just flag if not matching

    # snake_case
    if is_snake:
        val = re.sub(r"([A-Z])", r"_\1", value).lower()
        return val.strip("_")

    # kebab-case
    if is_kebab:
        val = re.sub(r"([A-Z])", lambda m: "-" + m.group(1).lower(), value)
        return val.lower().replace("_", "-")

    # CONSTANT_CASE
    if is_upper:
        return re.sub(r"[^A-Z0-9_]", "_", value.upper())

    # camelCase / PascalCase
    if is_camel:
        parts = re.split(r"[-_]+", value)
        if not parts:
            return value
        first = parts[0].lower()
        rest = "".join(p.capitalize() for p in parts[1:])
        return first + rest

    # --- Case 3: fallback heuristic ---
    # Try to make the string as minimally altered as possible to match the pattern
    cleaned = re.sub(r"[^a-zA-Z0-9/_:.~-]", "", value)
    return cleaned

def fix_selector(selector: str) -> str:
    # Guarantees prefix $
    if not selector.startswith("$"):
        selector = "$" + selector

    # Fixes $['key'] → $.key (only for simple keys, no special characters)
    selector = re.sub(r"\['([a-zA-Z0-9_]+)'\]", r".\1", selector)

    # Keeps $['/key-with-slash'] as $.paths["/key-with-slash"]
    selector = re.sub(r"\['(/[^']+)'\]", r'["\1"]', selector)

    # Also keeps other special characters inside ["..."]
    selector = re.sub(r"\['([^']*[^a-zA-Z0-9_][^']*)'\]", r'["\1"]', selector)

    # Fixes indexes [0] → [0] (jsonpath_ng accepts it directly, no need for .)
    # but if .$[0] comes in → transform it into [0]
    selector = selector.replace("$.[", "$[")

    return selector

def fix_scope(scope: str) -> str:
    scope = scope.lower()
    if "parameter" in scope:
        return "parameters"
    if "response" in scope:
        return "responses"
    if "schema" in scope:
        return "schemas"
    if "server" in scope:
        return "servers"
    if "info" in scope:
        return "info"
    return "paths"  # fallback padrão

def ensure_path(spec: dict, selector: str, default_value: dict):
    """
    Ensures the target node exists and injects default_value.
    Supports array fields using {"[url]": "TODO"} to indicate array-type nodes.
    Example: selector="$.servers" + default_value={"[url]":"TODO"} → creates:
             "servers": [ {"url": "TODO"} ]
    """
    # Detecta modo array
    array_mode = False
    array_field = None
    array_value = None

    if isinstance(default_value, dict) and len(default_value) == 1:
        k = next(iter(default_value.keys()))
        if isinstance(k, str) and k.startswith("[") and k.endswith("]"):
            array_mode = True
            array_field = k.strip("[]")
            array_value = default_value[k]

    # Verifica se o selector contém um bracket como $.paths['/x']
    m = _BRACKET_RE.match(selector)
    if m:
        root_prop, key, suffix = m.group(1), m.group(2), m.group(3)
        if root_prop not in spec or not isinstance(spec[root_prop], dict):
            spec[root_prop] = {}
        if key not in spec[root_prop] or not isinstance(spec[root_prop][key], dict):
            spec[root_prop][key] = {}

        node = spec[root_prop][key]

        # Cria dicionários intermediários (sufixo)
        if suffix:
            parts = [p for p in suffix.split('.') if p]
            cur = node
            for p in parts:
                if p.endswith(']') or p == '*' or p.endswith('*'):
                    break
                if p not in cur or not isinstance(cur[p], dict):
                    cur[p] = {}
                cur = cur[p]
        else:
            cur = node

        # Caso especial: array mode
        if array_mode:
            # Substitui o nó inteiro por uma lista
            spec[root_prop][key] = [{array_field: array_value}]
            return spec

        # Caso normal (dict)
        if isinstance(cur, dict):
            cur.update(default_value)
        return spec

    # Caso selector simples via jsonpath_ng
    expr = parse(selector)
    matches = expr.find(spec)

    if not matches:
        # Cria o caminho se ainda não existe
        if selector.startswith("$."):
            parts = [p for p in selector[2:].split('.') if p and p != '*']
            cur = spec
            for p in parts:
                if p.endswith(']'):
                    break
                if p not in cur or not isinstance(cur[p], dict):
                    cur[p] = {}
                cur = cur[p]
            if array_mode:
                cur_key = parts[-1] if parts else None
                if cur_key:
                    spec[cur_key] = [{array_field: array_value}]
                else:
                    spec[selector.strip("$.")] = [{array_field: array_value}]
            else:
                cur.update(default_value)
        return spec

    # Matches encontrados → aplica diretamente
    for m in matches:
        parent = m.context.value if m.context else spec
        key = str(m.path)

        if array_mode:
            # substitui o nó encontrado diretamente pelo array
            if isinstance(parent, dict):
                parent[key] = [{array_field: array_value}]
            elif isinstance(parent, list):
                for i in range(len(parent)):
                    parent[i] = {array_field: array_value}
        else:
            if isinstance(m.value, dict):
                m.value.update(default_value)

    return spec

def detect_oas_version_from_spec(spec: dict) -> str | None:
    """
    Detects the OAS version based on the loaded spec.
    Returns "oas2", "oas3", or None.
    """
    # if Swagger 2.0
    if "swagger" in spec and str(spec.get("swagger", "")).startswith("2"):
        return "oas2"
    # if OpenAPI 3.x
    if "openapi" in spec and str(spec.get("openapi", "")).startswith("3"):
        return "oas3"
    return None

# --------------------------------------
# Compatibility with format: $.paths['/investment-fund']
# jsonpath_ng does not have this compatibility
# --------------------------------------
def preprocess_selector(selector: str):
    """
    Converts selectors like $.paths['/some-path'] to $.paths.*,
    also returning the target key for manual filtering.
    """
    if "['" in selector:
        root, key = selector.split("['", 1)
        key = key.rstrip("']")
        return root + ".*", key
    return selector, None

_BRACKET_RE = re.compile(r"^\$\.(\w+)\['([^']+)'\](.*)$")

def find_with_rule_selector(rule: dict, spec: dict):
    """
    ALWAYS returns a list of Matches (DatumInContext).
    Accepts selectors like: $.paths['/investment-fund'](.suffixes...)
    and valid jsonpath_ng selectors (without brackets/quotes).
    """
    selector = rule["selector"]

    m = _BRACKET_RE.match(selector)
    if not m:
        # normal case: selector is already compatible with jsonpath_ng
        return parse(selector).find(spec)

    root_prop, key, suffix = m.group(1), m.group(2), m.group(3)  # ex: paths, '/investment-fund', '.get.responses'
    # 1) check root existence
    if root_prop not in spec or not isinstance(spec[root_prop], dict):
        return []  # nothing found; your ensure treats creation

    root_ctx = DatumInContext.wrap(spec)
    prop_ctx = DatumInContext(value=spec[root_prop], path=Fields(root_prop), context=root_ctx)

    if key not in spec[root_prop]:
        return []  # nothing found; ensure can create

    key_ctx = DatumInContext(value=spec[root_prop][key], path=Fields(key), context=prop_ctx)

    if not suffix:
        # match exactly the key node
        return [key_ctx]

    # 2) Apply the rest of the path from the base node
    # Ex.: suffix = ".get.responses" → apply to key_ctx.value
    # IMPORTANT: Keep the return value as Match; we will "rebase" the context.
    expr = parse(f"${suffix}")  # suffix starts with ".", e.g.: ".get..."
    sub_matches = expr.find(key_ctx.value)

    # rebase: preserves relative path (match.path), but anchors in key_ctx context
    rebased = [
        DatumInContext(value=sm.value, path=sm.path, context=key_ctx)
        for sm in sub_matches
    ]
    return rebased

# ---------------------------
# Validators
# ---------------------------

# Define valid properties for each JSON Schema type
ALLOWED_PROPERTIES = {
    "string": {"maxLength", "minLength", "pattern", "format", "enum"},
    "integer": {"minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "enum", "format"},
    "number": {"minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "enum", "format"},
    "boolean": set(),  # usually has no extra restrictions
    "array": {"items", "minItems", "maxItems", "uniqueItems"},
    "object": {"properties", "required", "additionalProperties"}
}

def match_field(name: str, field_pattern: str | None) -> bool:
    """Checks if the field name matches the pattern (or always True if field=None)."""
    if not field_pattern:
        return True
    return fnmatch.fnmatch(name.lower(), field_pattern.lower())

def apply_filter_generic(node, rule):
    """
    Supports:
      - field_equals: { "in": "query" }
      - field_in_list: { "name": ["page", "pagina"] }
      - field_not_in_list: { "in": ["header"] }
      - startswith / not_startswith
      - key_startswith / key_not_startswith
      - regex / not_regex
    """
    f = rule.get("filter")
    if not f:
        return True

    if any(k.startswith("field_") for k in f.keys()) and isinstance(node, dict):
        if "field_equals" in f:
            for fld, val in f["field_equals"].items():
                if node.get(fld) != val:
                    return False
        if "field_in_list" in f:
            for fld, lst in f["field_in_list"].items():
                if node.get(fld) not in lst:
                    return False
        if "field_not_in_list" in f:
            for fld, lst in f["field_not_in_list"].items():
                if node.get(fld) in lst:
                    return False
        if "field_regex" in f:
            for fld, pattern in f["field_regex"].items():
                val = str(node.get(fld, ""))
                if not re.compile(pattern).match(val):
                    return False
        if "field_not_regex" in f:
            for fld, pattern in f["field_not_regex"].items():
                val = str(node.get(fld, ""))
                if re.compile(pattern).match(val):
                    return False

    if isinstance(node, str):
        if "startswith" in f and not node.startswith(f["startswith"]):
            return False
        if "not_startswith" in f and node.startswith(f["not_startswith"]):
            return False
        if "regex" in f:
            if not re.compile(f["regex"]).match(node):
                return False
        if "not_regex" in f:
            if re.compile(f["not_regex"]).match(node):
                return False

    if isinstance(node, dict):
        if "key_startswith" in f:
            if not any(k.startswith(f["key_startswith"]) for k in node.keys()):
                return False
        if "key_not_startswith" in f:
            if any(k.startswith(f["key_not_startswith"]) for k in node.keys()):
                return False

    return True

def validate_rule(rule, spec, autofix_enabled=False):
    results = []
    current_oas_version = detect_oas_version_from_spec(spec)
    rule_version = rule["oas_version"]
    if rule_version is not None and current_oas_version is not None:
        if rule_version != current_oas_version:
            return None

    try:
        matches = find_with_rule_selector(rule, spec)

        if (rule["op"] == "ensure" or rule["op"] == "ensure_not") and matches == [] and (rule["oas_version"] is None or rule["oas_version"] == current_oas_version):
            ensure_path(spec, rule["selector"], default_value={rule["field"]: "TODO"})

    except Exception as ex:
        print("[Error]", rule["selector"], ex)
        return None

    op = rule["op"]
    field = rule.get("field")  # pode ter wildcard
    value = rule.get("value")
    methods = rule.get("methods")
    autofix = rule.get("autofix", False) and autofix_enabled
    force = rule.get("force", False)

    for m in matches:
        node = m.value

        if not apply_filter_generic(node, rule):
            continue

        # ---------------------------
        # ensure
        # ---------------------------
        if op == "ensure" or op == "ensure_not":
            allowed_methods = [m.lower() for m in rule.get("methods", [])]
            for m in matches:
                # If there is a restriction on methods, validate first
                if allowed_methods:
                    method_ok = any(f".{meth}." in str(m.full_path).lower() for meth in allowed_methods)
                    if not method_ok:
                        continue

                node = m.value

                if not apply_filter_generic(node, rule):
                    continue

                if isinstance(node, dict):
                    # If the rule depends on type → check in the array
                    node_type = node.get("type")

                    if node_type and field not in ALLOWED_PROPERTIES.get(node_type, set()):
                        #continue  # ignores invalid fields for that type
                        if node_type != "string":
                            continue

                    if field == "items" and node.get("type") != "array":
                        continue

                    if (op == "ensure" and field not in node) or (op == "ensure_not" and field in node):
                        new_result = {
                            "rule_code": rule["rule_code"],
                            "path": str(m.full_path),
                            "message": f"{rule['check_text']} (field '{field}' unavailable)",
                            "severity": rule["severity"]
                        }
                        if new_result not in results:
                            results.append(new_result)
                        if autofix:
                            if value is not None:
                                node[field] = value
                            else:
                                if field == "items":
                                    node[field] = {"type": "string"}
                                else:
                                    if field == "required":
                                        node[field] = []
                                    else:
                                        node[field] = f"TODO: fill {field}"
                    elif (op == "ensure") and ((node[field] is None or (isinstance(node[field], str) and not node[field].strip())) or force):
                        results.append({
                            "rule_code": rule["rule_code"],
                            "path": str(m.full_path),
                            "message": f"{rule['check_text']} (field '{field}' empty or null)",
                            "severity": rule["severity"]
                        })
                        if autofix:
                            if value is not None:
                                if not force:
                                    node[field] = value
                                else:
                                    try:
                                        node[field].update(value)
                                    except:
                                        node[field] = next(iter(value.values())) if len(value) == 1 else value
                            else:
                                node[field] = f"TODO: Fill {field}"

        # ---------------------------
        # unique
        # ---------------------------
        elif op == "unique":
            seen = set()
            if isinstance(node, list):
                for idx, param in enumerate(node):
                    for k, v in param.items():
                        if match_field(k, field):
                            if v in seen:
                                results.append({
                                    "rule_code": rule["rule_code"],
                                    "path": str(m.full_path) + f"[{idx}]",
                                    "message": f"Duplicated value in '{k}': {v}",
                                    "severity": rule["severity"]
                                })
                                if autofix:
                                    param[k] = f"{v}_dupfix"
                            else:
                                seen.add(v)

        # ---------------------------
        # regex
        # ---------------------------
        elif op == "regex":
            pattern = rule.get("pattern", r"^[a-z][a-zA-Z0-9]*$")
            regex = re.compile(pattern)
            check_text = rule.get("check_text", "Value does not follow the expected pattern")

            if isinstance(node, dict):
                for k in list(node.keys()):
                    if match_field(k, field):
                        if not regex.match(k):
                            results.append({
                                "rule_code": rule["rule_code"],
                                "path": str(m.full_path) + "." + k,
                                "message": f"{check_text}: '{k}'",
                                "severity": rule["severity"]
                            })
                            if autofix:
                                node[fix_with_pattern(k, pattern)] = node.pop(k)

            elif isinstance(node, str):
                if not regex.match(node):
                    results.append({
                        "rule_code": rule["rule_code"],
                        "path": str(m.full_path),
                        "message": f"{check_text}: '{node}'",
                        "severity": rule["severity"]
                    })
                    if autofix:
                        parent = m.context.value
                        key = str(m.path)
                        parent[key] = fix_with_pattern(node, pattern)

        elif op == "value_regex":
            pattern = rule["pattern"]
            regex = re.compile(pattern)
            replacement = rule.get("value")  # optional default value
            check_text = rule.get("check_text", "Value does not follow the expected pattern")

            for m in matches:
                node_val = m.value
                if isinstance(node_val, str):
                    if not regex.match(node_val):
                        results.append({
                            "rule_code": rule["rule_code"],
                            "path": str(m.full_path),
                            "message": f"{check_text}: '{node_val}'",
                            "severity": rule["severity"]
                        })
                        if autofix:
                            parent = m.context.value
                            key = str(m.path)
                            if replacement is not None:
                                parent[key] = replacement
                            else:
                                parent[key] = fix_with_pattern(node_val, pattern)
                            
        # ---------------------------
        # enum
        # ---------------------------
        elif op == "enum":
            if isinstance(node, dict):
                for k, v in node.items():
                    if match_field(k, field):
                        if v not in value:
                            results.append({
                                "rule_code": rule["rule_code"],
                                "path": str(m.full_path) + "." + k,
                                "message": f"Invalid value in '{k}': {v}",
                                "severity": rule["severity"]
                            })
                            if autofix:
                                node[k] = value[0]

        # ---------------------------
        # length
        # ---------------------------
        elif op == "length":
            if isinstance(node, dict):
                for prop_name, prop_def in node.items():
                    if match_field(prop_name, field) and prop_def.get("type") == "string":
                        min_len = value.get("min")
                        max_len = value.get("max")

                        if min_len and (prop_def.get("minLength") is None or prop_def["minLength"] < min_len):
                            results.append({
                                "rule_code": rule["rule_code"],
                                "path": str(m.full_path) + "." + prop_name,
                                "message": f"invalid minLength (< {min_len})",
                                "severity": rule["severity"]
                            })
                            if autofix:
                                prop_def["minLength"] = min_len

                        if max_len and (prop_def.get("maxLength") is None or prop_def["maxLength"] > max_len):
                            results.append({
                                "rule_code": rule["rule_code"],
                                "path": str(m.full_path) + "." + prop_name,
                                "message": f"invalid maxLength (> {max_len})",
                                "severity": rule["severity"]
                            })
                            if autofix:
                                prop_def["maxLength"] = max_len

        # ---------------------------
        # uniform_all
        # ---------------------------
        elif op == "uniform_all":
            field_defs = {}
            for m in matches:
                node = m.value
                if isinstance(node, dict):
                    for prop, definition in node.items():
                        if isinstance(definition, dict):
                            if prop not in field_defs:
                                field_defs[prop] = []
                            field_defs[prop].append((str(m.full_path), definition))

            # Now Compare
            for prop, occurrences in field_defs.items():
                if len(occurrences) > 1:
                    # Pega a primeira como baseline
                    baseline = occurrences[0][1]
                    for path, definition in occurrences[1:]:
                        diffs = []
                        for attr, val in baseline.items():
                            if attr in ["description", "example"]:  
                                continue  # ignore descriptives
                            if definition.get(attr) != val:
                                diffs.append((attr, definition.get(attr), val))
                        if diffs:
                            results.append({
                                "rule_code": rule["rule_code"],
                                "path": path,
                                "message": f"Field '{prop}' divergent: {diffs}",
                                "severity": rule["severity"]
                            })
                            if autofix:
                                for attr, wrong, correct in diffs:
                                    definition[attr] = correct

        # ---------------------------
        # update (via LLM)
        # ---------------------------
        elif op == "update":
            for m in matches:
                parent = m.value  # node corresponding to the selector

                if isinstance(parent, dict) and field not in parent \
                        and isinstance(m.context.value, dict) and field in m.context.value:
                    parent = m.context.value

                # 1. If it is a dictionary → rename key
                if isinstance(parent, dict) and field in parent:
                    if not isinstance(parent[field], (dict, list)):
                        if parent[field] != value:
                            results.append({
                                "rule_code": rule["rule_code"],
                                "path": str(m.full_path) + f".{field}",
                                "message": f"{rule['check_text']} (replace '{parent[field]}' → '{value}')",
                                "severity": rule["severity"]
                            })
                            if autofix:
                                parent[field] = value
                        continue
                    if value not in parent:  # only rename if it doesn't exist
                        results.append({
                            "rule_code": rule["rule_code"],
                            "path": str(m.full_path),
                            "message": f"{rule['check_text']} (rename key '{field}' → '{value}')",
                            "severity": rule["severity"]
                        })
                        if autofix:
                            rename_key_preserve_order(parent, field, value)

            # 2. If it is a list → replace value
                elif isinstance(parent, list):
                    for i, item in enumerate(parent):
                        if item == field:
                            results.append({
                                "rule_code": rule["rule_code"],
                                "path": str(m.full_path) + f"[{i}]",
                                "message": f"{rule['check_text']} (replace '{field}' → '{value}')",
                                "severity": rule["severity"]
                            })
                            if autofix:
                                parent[i] = value

                # 3. If it is a dict with a simple value (not a key) → replace the value
                elif isinstance(parent, dict):
                    if parent.get(field) and parent[field] != value:
                        old_val = parent[field]
                        results.append({
                            "rule_code": rule["rule_code"],
                            "path": str(m.full_path) + f".{field}",
                            "message": f"{rule['check_text']} (replace '{old_val}' → '{value}')",
                            "severity": rule["severity"]
                        })
                        if autofix:
                            parent[field] = value

    return results

# ---------------------------
# Dispatcher
# ---------------------------
def run_validator(spec_file, rules_file,
                  report_file="report.json",
                  spec_out="spec_fixed.json",
                  min_severity="info",
                  autofix_enabled=True):

    spec = load_spec(spec_file)
    rules = load_rules(rules_file)

    # -----------------------------
    # AI
    # -----------------------------
    print(f"\n🤖 AI Processing")
    ai_rules = analyze_with_llm_infinitive(spec)
    for r in ai_rules:
        r["selector"] = fix_selector(r["selector"])
        r["scope"] = fix_scope(r["scope"])
        rules.append(r)
    # print("AI Rules", rules)

    all_results = []
    for rule in rules:
        res = validate_rule(rule, spec, autofix_enabled)
        if res:
            filtered = [r for r in res if severity_allowed(r["severity"], min_severity)]
            all_results.extend(filtered)

    # Save report
    with open(report_file, "w", encoding="utf-8") as f:
        json.dump(all_results, f, indent=2, ensure_ascii=False)

    # If there is autofix, save corrected spec
    if autofix_enabled:
        with open(spec_out, "w", encoding="utf-8") as f:
            json.dump(spec, f, indent=2, ensure_ascii=False)

    print(f"[OK] Validation completed. Results in {report_file}. Spec fixed in {spec_out}")


# ---------------------------
# CLI
# ---------------------------
if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Uso: python rules_dispatcher.py <openapi.json|yaml> <rules.json> [--min-severity warning|error]")
        sys.exit(1)

    spec_file = sys.argv[1]
    rules_file = sys.argv[2]

    min_severity = "info"
    if "--min-severity" in sys.argv:
        idx = sys.argv.index("--min-severity")
        if idx + 1 < len(sys.argv):
            min_severity = sys.argv[idx + 1]

    run_validator(spec_file, rules_file, min_severity=min_severity, autofix_enabled=True)