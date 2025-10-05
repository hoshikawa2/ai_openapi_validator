import json
import re
import sys
from pathlib import Path
from PyPDF2 import PdfReader
from langchain_ollama import ChatOllama
from tqdm import tqdm
import ruamel.yaml
from collections import OrderedDict

# -------------------------
# 1. Extract rules from PDF
# -------------------------
def extract_rules_from_pdf(file_path: str):
    reader = PdfReader(file_path)
    rules = []
    for page in reader.pages:
        text = page.extract_text()
        if not text:
            continue
        for line in text.split("\n"):
            line = line.strip()
            if line and len(line.split()) > 3:
                rules.append(line)
    return rules

def detect_oas_version(text: str) -> str | None:
    if re.search(r"\bswagger\s*:?[\s]*2(\.0)?\b", text, re.IGNORECASE):
        return "oas2"
    if re.search(r"\bopenapi\s*:?[\s]*3(\.\d+)?\b", text, re.IGNORECASE):
        return "oas3"
    if re.search(r"\boas2\s*:?[\s]*2(\.0)?\b", text, re.IGNORECASE):
        return "oas2"
    if re.search(r"\boas3\s*:?[\s]*3(\.\d+)?\b", text, re.IGNORECASE):
        return "oas3"
    if "oas2" in text.lower():
        return "oas2"
    if "oas3" in text.lower():
        return "oas3"
    return None

# -------------------------
# 2. Configure LLM Ollama
# llama3:70b-instruct
# mistral:instruct
# -------------------------
llm = ChatOllama(
    base_url="http://127.0.0.1:11434",
    model="llama3:70b-instruct",
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

# -------------------------
# 3. Interpretar regra
# -------------------------
def interpret_rule(rule_text: str, spec_text: str, idx: int):
    prompt = f"""
    You are an OpenAPI/Swagger rules parser.

    Your task is to:
    1. Read the rule below.
    2. Extract the rule code (e.g., R32, R58, R01).
    3. Classify the rule as exactly **one** of the following operation types:
    [ensure, unique, regex, value_regex, enum, length, uniform_all, update, OTHER]

    ⚠️ How to choose correctly:
    ### Instructions on how to classify `op`

    - ensure: Used when the rule requires a field to exist.
    Examples:
    "Responses must contain 200" → field="200"
    "Every response must have a description" → field="description"
    "Schemas and properties must have a description" → field="description"
    ⚠️ Even if the field is described generically (e.g., *description*), always use op="ensure". 
    **Do not invent random values (e.g., ranges, -x). Just ensure the presence or fixed value.**

    - unique: Used when the rule prohibits duplication.
    Example: "operationId must be unique."

    - regex: Used to validate the format of attribute or parameter names.
    Must include "pattern".
    Example: "names must be in lowerCamelCase" → pattern="^[a-z][a-zA-Z0-9]*$".

    - value_regex: Used to validate the content of a string value (URLs, textual patterns).
    Must include "pattern" and, optionally, a suggested "value".
    Example: "url must start with http://Backend_Path/" → pattern="^http://Backend_Path/.*$".

    - enum: Used for rules that restrict values to a fixed set.
    Must include "value" with a list of accepted values.
    Example: "type must be string, integer, or boolean".

    - length: Used to validate string length.
    Must include "value": {{"min": X, "max": Y}}.
    Example: "CPF must have exactly 11 characters."

    - uniform_all: Used when the rule requires consistency between repeated definitions.
    Example: "Fields with the same name must have the same configuration."

    - update: Used when it becomes necessary to update the attribute or parameter name with another one.
    Example: "Endpoints must be plural," "Replace the attribute name," "Update the attribute with"

    - other: If it does not fit into any of the categories.

    ⚠️ Additional fields:
    - If the rule mentions specific HTTP methods (GET, POST, PUT, PATCH, DELETE), include `"methods": ["get", "post", ...]`.
    - scope must be one of: "responses", "parameters", "schema", "schema properties", "operations", "servers", "OTHER".
    - field must be the target field or "*" if generic. Never generate more than one field.
    - severity must be "error" or "warning".
    - autofix must always be Boolean.

    ⚠️ The `selector` field must always be compatible with the jsonpath_ng library (JSONPath). - Always use the base specification to build the selector.
    ⚠️ Never use periods with version numbers (e.g., v3.0.1) in the selector.
    ⚠️ Never use concatenated fields with typos in the selector.
    ⚠️ Never use quotes within selectors.
    - Always generate a single selector.
    - A selector should NEVER contain: square brackets with quotes, compound paths (`"a.b"`), version names (`openapi.v3.0.1`), or non-existent operators.
    ⚠️ The `selector` field can never contain:
    - `*/*`
    - `/#/`
    - commas `,`
    - filters `?(@...)`
    - operators `=`, `!=`, `OR`, `split()`
    - names with `:` (e.g., `ui:swagger`)
    - malformed `$ref` (only use `$.components.schemas.*.$ref` or `$.paths.*.*.responses.*.$ref`)
    - stray tokens (`example`, `ref`, etc.)
    If the rule suggests something that requires filters, functions, multiple selectors, or unsupported operators,
    use exactly: `"selector": "$.OTHER"`.

    ⚠️ IMPORTANT RULES FOR THE FINAL JSON:
    - ALWAYS required fields:
    rule_code, summary, scope, op, selector, field, check_text, severity, hints, autofix
    - The `op` field is **always required**. If you're unsure which to use, set `op`: "OTHER".
    - Don't leave any fields blank or missing.
    - If `op` = "regex" or "value_regex", also include `pattern`.
    - If `op` = "enum", also include `value` as a list of values.
    - If `op` = "length", also include `value` in the format {{"min": X, "max": Y}}.
    - If `op` = "uniform_all", there is no `pattern` or `value`, only `check_text`. - If `op` = "update", there is no `pattern`, just the `field` field which must contain the original value to be updated and the `value` field which is **required** and must contain the new replacement value.

    ⚠️ Style:
    - Never omit fields, even if you need to use plausible values.

    ⚠️ Output JSON MUST have all human-readable text fields (summary, check_text, hints) written in Portuguese, regardless of the input language

    Valid examples:

    - ensure:
    {{
        "rule_code": "R01",
        "summary": "Responses must contain 200",
        "scope": "responses",
        "op": "ensure",
        "selector": "$.paths.*.*.responses",
        "field": "200",
        "check_text": "All operations must have a 200 response",
        "severity": "error",
        "autofix": true,
        "hints": ["Add responses.200 with description"]
    }}

    - unique:
    {{
        "rule_code": "R07",
        "summary": "operationId must be unique",
        "scope": "operations",
        "op": "unique",
        "selector": "$.paths.*.*",
        "field": "operationId",
        "check_text": "Each operation must have a unique operationId",
        "severity": "error",
        "autofix": true,
        "hints": ["Rename duplicate operationIds"]
    }}

    - regex:
    {{
        "rule_code": "R52",
        "summary": "Parameters in lowerCamelCase",
        "scope": "parameters",
        "op": "regex",
        "selector": "$.paths.*.*.parameters[*].name",
        "pattern": "^[a-z][a-zA-Z0-9]*$",
        "field": "name",
        "check_text": "Parameters must follow lowerCamelCase",
        "severity": "warning",
        "autofix": true,
        "hints": ["Example: investmentFundName"]
    }}

    - value_regex:
    {{
        "rule_code": "R52",
        "summary": "URLs must start with http://Backend_path/",
        "scope": "servers",
        "op": "value_regex",
        "selector": "$.servers[*].url",
        "pattern": "^http://Backend_path/.*$",
        "field": "url",
        "check_text": "The 'url' field must start with 'http://Backend_path/'",
        "severity": "error",
        "autofix": true,
        "value": "http://Backend_path/api/fees/v2",
        "hints": ["Fix the value to start with http://Backend_path/"]
    }}

    - enum:
    {{
        "rule_code": "R05",
        "summary": "Type must be in the allowed set",
        "scope": "schema properties",
        "op": "enum",
        "selector": "$.components.schemas.*.properties.*",
        "field": "type",
        "value": ["string", "integer", "boolean", "number"],
        "check_text": "Types must be in the allowed set",
        "severity": "error",
        "autofix": true,
        "hints": ["Check if 'type' follows the JSON Schema standard"]
    }}

    - length:
    {{
        "rule_code": "R11",
        "summary": "CPF must have 11 characters",
        "scope": "schema properties",
        "op": "length",
        "selector": "$.components.schemas.*.properties",
        "field": "*cpf*",
        "value": {{"min": 11, "max": 11}},
        "check_text": "Any field containing 'cpf' in the name must have exactly 11 characters",
        "severity": "error",
        "autofix": true,
        "hints": ["Set minLength=11 and maxLength=11"]
    }}

    - uniform_all:
    {{
        "rule_code": "R58",
        "summary": "Properties with the same name must have a uniform definition",
        "scope": "schema+parameters",
        "op": "uniform_all",
        "selector": "$.components.schemas.*.properties",
        "field": "*",
        "check_text": "Fields that are the same in different locations must have the same attributes",
        "severity": "error",
        "autofix": true,
        "hints": ["Example: managerDocumentNumber must always have {{type=string, maxLength=14}}"]
    }}

    - update:
    {{
        "rule_code": "LLM01",
        "summary": "Endpoints must be plural",
        "scope": "paths",
        "op": "update",
        "selector": "$.paths",
        "field": "/investment-fund",
        "value": "/investment-funds",
        "check_text": "Endpoints must be plural",
        "severity": "warning",
        "autofix": true,
        "hints": ["Always use resource names in the plural"]
    }}

    Rule {idx}:
    {rule_text}

    Base specification:
    {spec_text}

    Respond only with valid JSON.
    """

    response = llm.invoke(prompt)

    raw = response.content.strip()

    if not raw:
        raise ValueError(f"LLM's empty response to rule {idx}")

    # Extrair apenas o JSON
    start = raw.find("{")
    end = raw.rfind("}") + 1
    if start == -1 or end == -1:
        # raise ValueError(f"Nenhum JSON encontrado (regra {idx})")
        return {
            "rule_code": f"R_FAIL_{idx}",
            "summary": "Failure to interpret",
            "scope": "OTHER",
            "op": "OTHER",
            "selector": "$",
            "field": "*",
            "check_text": "Error decoding rule",
            "severity": "error",
            "hints": ["Manually review"],
            "autofix": False
        }

    raw_json = raw[start:end]

    def sanitize(text: str) -> str:
        text = text.replace("'", '"')  
        text = re.sub(r",(\s*[}\]])", r"\1", text)  
        text = text.replace("\\", "\\\\")  
        return text

    try:
        rule_obj = json.loads(raw_json)
        rule_obj["oas_version"] = detect_oas_version(rule_text)
        return rule_obj
    except json.JSONDecodeError:
        print(f"⚠️ Invalid JSON in rule {idx}, trying to fix...")
        safe = sanitize(raw_json)
        try:
            rule_obj = json.loads(safe)
            rule_obj["oas_version"] = detect_oas_version(rule_text)
            return rule_obj
        except json.JSONDecodeError as e:
            print(f"❌ Failed to fix rule JSON {idx}: {e}")
            return {
                "rule_code": f"R_FAIL_{idx}",
                "oas_version": None,
                "summary": "Failure to interpret",
                "scope": "OTHER",
                "op": "OTHER",
                "selector": "$",
                "field": "*",
                "check_text": "Error decoding rule",
                "severity": "error",
                "hints": ["Manually review"],
                "autofix": False
            }

# -------------------------
# 4. Orquestrate pipeline
# -------------------------
def process_pdf_with_llm(pdf_file: str, spec_text: str, output_file="rules.json"):
    rules_texts = extract_rules_from_pdf(pdf_file)
    results = []

    for idx, rule_text in enumerate(tqdm(rules_texts, desc="Processing rules"), start=1):
        rule_json = interpret_rule(rule_text, spec_text, idx)
        results.append(rule_json)

        # prints the rule and the corresponding json on the screen
        print("\n📌 Rule found:")
        print(rule_text)
        print("➡️ Generated JSON:")
        print(json.dumps(rule_json, indent=2, ensure_ascii=False))

    Path(output_file).write_text(
        json.dumps(results, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )
    print(f"\n✅ {len(results)} exported rules → {output_file}")


# -------------------------
# 5. CLI
# -------------------------
if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Uso: python rules_from_pdf.py <arquivo.pdf> <spec_base.json/yaml> [saida.json]")
        sys.exit(1)

    pdf_file = sys.argv[1]
    spec_file = sys.argv[2]
    output_file = sys.argv[3] if len(sys.argv) > 2 else "rules.json"

    spec_text = load_spec(spec_file)

    process_pdf_with_llm(pdf_file, spec_text, output_file)