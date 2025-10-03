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
# Severidade
# ---------------------------
SEVERITY_LEVELS = {"info": 1, "warning": 2, "error": 3}


def severity_allowed(rule_severity, min_severity):
    return SEVERITY_LEVELS[rule_severity] >= SEVERITY_LEVELS[min_severity]

# -------------------------
# 2. Configurar LLM Ollama
# -------------------------
llm = ChatOllama(
    base_url="http://127.0.0.1:11434",
    model="mistral:instruct",
    temperature=0.0,
    num_ctx=8192
)

# ---------------------------
# Carregadores
# ---------------------------
def load_spec(file_path: str):
    """Carrega a especificação OpenAPI em JSON/YAML."""
    path = Path(file_path)
    yaml = ruamel.yaml.YAML(typ="safe")

    with open(path, "r", encoding="utf-8") as f:
        if path.suffix.lower() in [".yaml", ".yml"]:
            return yaml.load(f)
        return json.load(f, object_pairs_hook=OrderedDict)


def load_rules(file_path: str):
    """Carrega regras em JSON."""
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)

# ---------------------------
# AI
# ---------------------------
def analyze_with_llm_plural(spec_text: str) -> list[dict]:
    """
    Analisa a especificação OpenAPI inteira usando LLM
    e retorna um array JSON de regras de update.
    """

    prompt = f"""
    Você é um analisador inteligente de especificações OpenAPI/Swagger.

    Sua tarefa:
    1. Leia cuidadosamente a especificação OpenAPI abaixo.
    2. Identifique inconsistências ou melhorias que não podem ser tratadas de forma determinística
       (exemplo: plural vs singular, nomes incoerentes, inconsistência de maiúsculas, 
       termos abreviados ou longos demais, inconsistência semântica).
    3. Para cada caso, crie uma regra de atualização JSON com:
       - rule_code: "LLMxx" (um código único por regra sugerida)
       - summary: resumo do problema
       - scope: nível do problema ("paths", "parameters", "schemas", "responses", "servers", etc.)
       - op: sempre "update"
       - selector: um JSONPath que aponte para onde o problema ocorre, sendo **SEMPRE** compatível com `jsonpath_ng`
       - field: o nome ou chave que deve ser substituída
       - value: o novo valor sugerido (corrigido)
       - check_text: texto explicativo do problema
       - severity: "error" ou "warning"
       - autofix: sempre true
       - hints: array de dicas de como evitar o problema
       - oas_version: null

    ⚠️ REGRAS IMPORTANTES
    - Responda **apenas com JSON válido** (um array de objetos).
    - Todos os campos são obrigatórios.
    - Seja preciso: se encontrar "/investment-fund", sugira "/investment-funds".
    - Não invente endpoints ou campos que não existam na especificação.
    - Trabalhe em português nos campos textuais (summary, check_text, hints).

    ⚠️ REGRAS DE FORMATAÇÃO PARA JSONPATH_NG
    - Sempre use um selector ABSOLUTO começando com `$.`
    - Nunca use `$[0]` ou seletores de índice logo após `$`. 
      * Se precisar acessar um elemento de array, use o caminho até a lista e depois o índice: 
        ✅ `$.paths["/users"].get.parameters[0].name`
    - Nunca use colchetes com aspas simples `['campo']`.
      * Para chaves simples (sem caracteres especiais): use `.campo` → `$.info.version`
      * Para chaves com caracteres especiais (ex: `/`, `-`, espaço): use colchetes com aspas duplas → 
        ✅ `$.paths["/investment-fund"]`
    - Para índices em arrays, use `[N]` direto, sem ponto antes: 
        ✅ `parameters[0].name`
        ❌ `parameters.[0].name`
    - O `selector` deve apontar até o OBJETO PAI.
    - O `field` deve conter a chave que será alterada dentro desse objeto.
    - O `value` deve ser o novo valor.

    Exemplo de saída esperada:

    [
      {{
        "rule_code": "LLM01",
        "summary": "Endpoints devem estar no plural",
        "scope": "paths",
        "op": "update",
        "selector": "$.paths",
        "field": "/investment-fund",
        "value": "/investment-funds",
        "check_text": "Endpoints devem estar no plural",
        "severity": "warning",
        "autofix": true,
        "hints": ["Use nomes de recursos sempre no plural, ex: /customers, /orders"],
        "oas_version": null
      }}
    ]

    Especificação para análise:
    {spec_text}
    """

    response = llm.invoke(prompt)

    raw = response.content.strip()

    # print(f"\n--- Resposta crua da LLM para regra ---")
    # print(raw)
    # print("--------------------------------------------")

    if not raw:
        raise ValueError(f"Resposta vazia da LLM para regra")

    # Extrair apenas o JSON
    start = raw.find("[")
    end = raw.rfind("]") + 1
    if start == -1 or end == -1:
        # raise ValueError(f"Nenhum JSON encontrado ")
        return {
            "rule_code": f"R_FAIL_AI",
            "summary": "Falha ao interpretar",
            "scope": "OTHER",
            "op": "OTHER",
            "selector": "$",
            "field": "*",
            "check_text": "Erro ao decodificar regra",
            "severity": "error",
            "hints": ["Revisar manualmente"],
            "autofix": False,
            "oas_version": None
        }

    raw_json = raw[start:end]

    def sanitize(text: str) -> str:
        text = text.replace("'", '"')  # força aspas duplas
        text = re.sub(r",(\s*[}\]])", r"\1", text)  # remove vírgula sobrando
        text = text.replace("\\", "\\\\")  # corrige escapes
        text = text.replace("\nNone\n", "null")
        return text

    try:
        parsed = json.loads(raw_json)
    except json.JSONDecodeError:
        print("⚠️ JSON inválido na regra, tentando corrigir...")
        safe = sanitize(raw_json)
        try:
            parsed = json.loads(safe)
        except json.JSONDecodeError as e:
            print(f"❌ Falha ao corrigir JSON da regra: {e}")
            return [{
                "rule_code": "R_FAIL_AI",
                "summary": "Falha ao interpretar",
                "scope": "OTHER",
                "op": "OTHER",
                "selector": "$",
                "field": "*",
                "check_text": "Erro ao decodificar regra",
                "severity": "error",
                "hints": ["Revisar manualmente"],
                "autofix": False,
                "oas_version": None
            }]

    # 🔑 Normalização: garantir sempre lista
    if isinstance(parsed, dict):
        return [parsed]
    elif isinstance(parsed, list):
        return parsed
    else:
        return [{
            "rule_code": "R_FAIL_AI",
            "summary": "Resposta inesperada (não é lista nem dict)",
            "scope": "OTHER",
            "op": "OTHER",
            "selector": "$",
            "field": "*",
            "check_text": "Erro ao decodificar regra",
            "severity": "error",
            "hints": ["Revisar manualmente"],
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
    """Tenta corrigir `value` para que obedeça ao `pattern`."""
    regex = re.compile(pattern)

    # Se já está ok, retorna
    if regex.match(value):
        return value

    # Catálogo de padrões conhecidos
    if pattern == r"^[a-z][a-zA-Z0-9]*$":  # camelCase
        new_val = re.sub(r"[-_]+([a-zA-Z])", lambda m: m.group(1).upper(), value)
        return new_val[0].lower() + new_val[1:]
    elif pattern == r"^[a-z]+(_[a-z0-9]+)*$":  # snake_case
        new_val = re.sub(r"([A-Z])", r"_\1", value).lower()
        return new_val.strip("_")
    elif pattern == r"^[a-z][a-z0-9-]*$":  # kebab-case
        new_val = re.sub(r"([A-Z])", lambda m: "-" + m.group(1).lower(), value)
        return new_val.lower().replace("_", "-")
    elif pattern == r"^[a-z]*$":  # só minúsculas
        return re.sub(r"[^a-z]", "", value.lower())
    elif pattern == r"^[A-Z0-9_]+$":  # CONSTANT_CASE
        return re.sub(r"[^A-Z0-9_]", "", value.upper())

    # Heurísticas genéricas
    if "a-z" in pattern and not "A-Z" in pattern:
        return re.sub(r"[^a-z0-9]", "", value.lower())
    if "A-Z" in pattern and not "a-z" in pattern:
        return re.sub(r"[^A-Z0-9]", "", value.upper())
    if "-" in pattern:
        return value.replace("_", "-").lower()
    if "_" in pattern:
        return value.replace("-", "_").lower()

    # fallback: tenta só forçar match
    return value

def fix_selector(selector: str) -> str:
    # Garante prefixo $
    if not selector.startswith("$"):
        selector = "$" + selector

    # Corrige $['chave'] → $.chave   (somente para chaves simples, sem caracteres especiais)
    selector = re.sub(r"\['([a-zA-Z0-9_]+)'\]", r".\1", selector)

    # Mantém $['/chave-com-slash'] como $.paths["/chave-com-slash"]
    selector = re.sub(r"\['(/[^']+)'\]", r'["\1"]', selector)

    # Mantém também outros caracteres especiais dentro de ["..."]
    selector = re.sub(r"\['([^']*[^a-zA-Z0-9_][^']*)'\]", r'["\1"]', selector)

    # Corrige índices [0] → [0] (jsonpath_ng aceita direto, não precisa do .)
    # mas se vier .$[0] → transforma em [0]
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
    Garante a existência do nó-alvo e injeta default_value (ex.: {"field":"TODO"}).
    Compatível com $.paths['/algo'] e com seletores jsonpath_ng simples.

    Observação: este ensure é seguro para nós do tipo dict.
    Para seletores que terminam em array (ex.: parameters[*]) é melhor ter um ensure específico.
    """
    m = _BRACKET_RE.match(selector)
    if m:
        root_prop, key, suffix = m.group(1), m.group(2), m.group(3)

        # cria root se faltar
        if root_prop not in spec or not isinstance(spec[root_prop], dict):
            spec[root_prop] = {}

        # cria a chave se faltar
        if key not in spec[root_prop] or not isinstance(spec[root_prop][key], dict):
            spec[root_prop][key] = {}

        node = spec[root_prop][key]

        # se houver sufixo tipo ".get.responses", vamos criar a trilha de dicts
        # (não tratamos wildcards/arrays aqui)
        if suffix:
            parts = [p for p in suffix.split('.') if p]  # remove vazio da borda
            cur = node
            for p in parts:
                # pare se bater em curinga/array; esse ensure é só para dict
                if p.endswith(']') or p == '*' or p.endswith('*'):
                    break
                if p not in cur or not isinstance(cur[p], dict):
                    cur[p] = {}
                cur = cur[p]
            # injeta default no nível alcançado
            if isinstance(cur, dict):
                cur.update(default_value)
            return spec

        # sem sufixo: injeta direto no nó da chave
        if isinstance(node, dict):
            node.update(default_value)
        return spec

    # caminho já simples jsonpath_ng → aplicar nos matches e injetar
    expr = parse(selector)
    matches = expr.find(spec)
    if not matches:
        # criar cadeia de dicts básica quando possível (ex.: $.components.schemas)
        # heurística simples: $.a.b.c → criar dicionários se faltarem
        if selector.startswith("$."):
            parts = [p for p in selector[2:].split('.') if p and p != '*']
            cur = spec
            for p in parts:
                if p.endswith(']'):  # arrays/índices/curingas: sair
                    break
                if p not in cur or not isinstance(cur[p], dict):
                    cur[p] = {}
                cur = cur[p]
            if isinstance(cur, dict):
                cur.update(default_value)
        return spec

    # matches existem → injeta em cada dict encontrado
    for m in matches:
        if isinstance(m.value, dict):
            m.value.update(default_value)
    return spec

def detect_oas_version_from_spec(spec: dict) -> str | None:
    """
    Detecta a versão do OAS com base na spec carregada.
    Retorna "oas2", "oas3" ou None.
    """
    # Se for Swagger 2.0
    if "swagger" in spec and str(spec.get("swagger", "")).startswith("2"):
        return "oas2"
    # Se for OpenAPI 3.x
    if "openapi" in spec and str(spec.get("openapi", "")).startswith("3"):
        return "oas3"
    return None

# --------------------------------------
# Compatibilidade com formato: $.paths['/investment-fund']
# jsonpath_ng nao possui esta compatibilidade
# --------------------------------------
def preprocess_selector(selector: str):
    """
    Converte selectors tipo $.paths['/algum-path'] em $.paths.*,
    retornando também a chave alvo para filtrar manualmente.
    """
    if "['" in selector:
        root, key = selector.split("['", 1)
        key = key.rstrip("']")
        return root + ".*", key
    return selector, None

_BRACKET_RE = re.compile(r"^\$\.(\w+)\['([^']+)'\](.*)$")

def find_with_rule_selector(rule: dict, spec: dict):
    """
    Retorna SEMPRE uma lista de Match (DatumInContext).
    Aceita seletores como: $.paths['/investment-fund'](.sufixos...)
    e seletores jsonpath_ng válidos (sem colchetes/aspas).
    """
    selector = rule["selector"]

    m = _BRACKET_RE.match(selector)
    if not m:
        # caso normal: selector já é compatível com jsonpath_ng
        return parse(selector).find(spec)

    root_prop, key, suffix = m.group(1), m.group(2), m.group(3)  # ex: paths, '/investment-fund', '.get.responses'
    # 1) checar existência do root
    if root_prop not in spec or not isinstance(spec[root_prop], dict):
        return []  # nada encontrado; seu ensure trata criação

    root_ctx = DatumInContext.wrap(spec)
    prop_ctx = DatumInContext(value=spec[root_prop], path=Fields(root_prop), context=root_ctx)

    if key not in spec[root_prop]:
        return []  # nada encontrado; ensure pode criar

    key_ctx = DatumInContext(value=spec[root_prop][key], path=Fields(key), context=prop_ctx)

    if not suffix:
        # match exatamente o nó da chave
        return [key_ctx]

    # 2) aplicar o restante do caminho a partir do nó base
    #    Ex.: suffix = ".get.responses"  → aplicar em key_ctx.value
    #    IMPORTANTE: manter retorno como Match; vamos "rebasear" o contexto.
    expr = parse(f"${suffix}")  # suffix começa com ".", ex.: ".get..."
    sub_matches = expr.find(key_ctx.value)

    # rebase: preserva path relativo (match.path), mas ancora no contexto key_ctx
    rebased = [
        DatumInContext(value=sm.value, path=sm.path, context=key_ctx)
        for sm in sub_matches
    ]
    return rebased

# ---------------------------
# Validadores
# ---------------------------

# Define propriedades válidas para cada tipo JSON Schema
ALLOWED_PROPERTIES = {
    "string": {"maxLength", "minLength", "pattern", "format", "enum"},
    "integer": {"minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "enum", "format"},
    "number": {"minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "enum", "format"},
    "boolean": set(),  # normalmente não tem restrições extras
    "array": {"items", "minItems", "maxItems", "uniqueItems"},
    "object": {"properties", "required", "additionalProperties"}
}

def match_field(name: str, field_pattern: str | None) -> bool:
    """Verifica se o nome do campo casa com o padrão (ou sempre True se field=None)."""
    if not field_pattern:
        return True
    return fnmatch.fnmatch(name.lower(), field_pattern.lower())

def validate_rule(rule, spec, autofix_enabled=False):
    results = []
    current_oas_version = detect_oas_version_from_spec(spec)
    rule_version = rule["oas_version"]
    # print(f"Versão detectada da spec: {current_oas_version}")
    if rule_version is not None and current_oas_version is not None:
        if rule_version != current_oas_version:
            return None

    try:
        # selector = parse(rule["selector"])
        # matches = selector.find(spec)
        matches = find_with_rule_selector(rule, spec)

        if rule["op"] == "ensure" and matches == [] and (rule["oas_version"] is None or rule["oas_version"] == current_oas_version):
            ensure_path(spec, rule["selector"], default_value={rule["field"]: "TODO"})

    except:
        print("[Error]", rule["selector"])
        return None

    op = rule["op"]
    field = rule.get("field")  # pode ter wildcard
    value = rule.get("value")
    methods = rule.get("methods")
    autofix = rule.get("autofix", False) and autofix_enabled

    for m in matches:
        node = m.value

        # if methods:
        #     if not any(f"['{meth}']" in str(m.full_path) for meth in methods):
        #         continue

        # ---------------------------
        # ensure
        # ---------------------------
        if op == "ensure":
            allowed_methods = [m.lower() for m in rule.get("methods", [])]
            for m in matches:
                # Se houver restrição de métodos, validar antes
                if allowed_methods:
                    method_ok = any(f".{meth}." in str(m.full_path).lower() for meth in allowed_methods)
                    if not method_ok:
                        continue

                node = m.value
                if isinstance(node, dict):
                    # Se a regra depende de tipo → verificar na matriz
                    node_type = node.get("type")
                    if node_type and field not in ALLOWED_PROPERTIES.get(node_type, set()):
                        continue  # ignora campos inválidos para esse tipo

                    if field == "items" and node.get("type") != "array":
                        continue

                    if field not in node:
                        results.append({
                            "rule_code": rule["rule_code"],
                            "path": str(m.full_path),
                            "message": f"{rule['check_text']} (campo '{field}' ausente)",
                            "severity": rule["severity"]
                        })
                        if autofix:
                            if field == "description":
                                node[field] = "TODO: preencher descrição"
                            elif field == "items":
                                node[field] = {"type": "string"}
                            elif field == "required":
                                node[field] = []
                            else:
                                node[field] = f"TODO: preencher {field}"

                    elif node[field] is None or (isinstance(node[field], str) and not node[field].strip()):
                        results.append({
                            "rule_code": rule["rule_code"],
                            "path": str(m.full_path),
                            "message": f"{rule['check_text']} (campo '{field}' vazio ou nulo)",
                            "severity": rule["severity"]
                        })
                        if autofix:
                            if field == "description":
                                node[field] = "TODO: preencher descrição"
                            else:
                                node[field] = f"TODO: preencher {field}"

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
                                    "message": f"Valor duplicado em '{k}': {v}",
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
            check_text = rule.get("check_text", "Valor não segue o padrão esperado")

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
            replacement = rule.get("value")  # valor padrão opcional
            check_text = rule.get("check_text", "Valor não segue o padrão esperado")

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
                                "message": f"Valor inválido em '{k}': {v}",
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
                                "message": f"minLength inválido (< {min_len})",
                                "severity": rule["severity"]
                            })
                            if autofix:
                                prop_def["minLength"] = min_len

                        if max_len and (prop_def.get("maxLength") is None or prop_def["maxLength"] > max_len):
                            results.append({
                                "rule_code": rule["rule_code"],
                                "path": str(m.full_path) + "." + prop_name,
                                "message": f"maxLength inválido (> {max_len})",
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

            # Agora comparar
            for prop, occurrences in field_defs.items():
                if len(occurrences) > 1:
                    # Pega a primeira como baseline
                    baseline = occurrences[0][1]
                    for path, definition in occurrences[1:]:
                        diffs = []
                        for attr, val in baseline.items():
                            if attr in ["description", "example"]:  
                                continue  # ignorar descritivos
                            if definition.get(attr) != val:
                                diffs.append((attr, definition.get(attr), val))
                        if diffs:
                            results.append({
                                "rule_code": rule["rule_code"],
                                "path": path,
                                "message": f"Campo '{prop}' divergente: {diffs}",
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
                parent = m.value  # nó correspondente ao selector

                # 1. Caso seja um dicionário → renomear chave
                if isinstance(parent, dict) and field in parent:
                    if value not in parent:  # só renomeia se não existir
                        results.append({
                            "rule_code": rule["rule_code"],
                            "path": str(m.full_path),
                            "message": f"{rule['check_text']} (renomear chave '{field}' → '{value}')",
                            "severity": rule["severity"]
                        })
                        if autofix:
                            # parent[value] = parent.pop(field)
                            rename_key_preserve_order(parent, field, value)

            # 2. Caso seja lista → substituir valor
                elif isinstance(parent, list):
                    for i, item in enumerate(parent):
                        if item == field:
                            results.append({
                                "rule_code": rule["rule_code"],
                                "path": str(m.full_path) + f"[{i}]",
                                "message": f"{rule['check_text']} (substituir '{field}' → '{value}')",
                                "severity": rule["severity"]
                            })
                            if autofix:
                                parent[i] = value

                # 3. Caso seja dict com valor simples (não chave) → substituir valor
                elif isinstance(parent, dict):
                    if parent.get(field) and parent[field] != value:
                        old_val = parent[field]
                        results.append({
                            "rule_code": rule["rule_code"],
                            "path": str(m.full_path) + f".{field}",
                            "message": f"{rule['check_text']} (substituir '{old_val}' → '{value}')",
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
                  spec_out="spec_corrigida.json",
                  min_severity="info",
                  autofix_enabled=True):

    spec = load_spec(spec_file)
    rules = load_rules(rules_file)

    # -----------------------------
    # AI
    # -----------------------------
    print(f"\n🤖 Processamento IA")
    ai_rules = analyze_with_llm_plural(spec)
    for r in ai_rules:
        r["selector"] = fix_selector(r["selector"])
        r["scope"] = fix_scope(r["scope"])
        rules.append(r)
    print("AI Rules", rules)

    all_results = []
    for rule in rules:
        res = validate_rule(rule, spec, autofix_enabled)
        if res:
            filtered = [r for r in res if severity_allowed(r["severity"], min_severity)]
            all_results.extend(filtered)

    # Salva relatório
    with open(report_file, "w", encoding="utf-8") as f:
        json.dump(all_results, f, indent=2, ensure_ascii=False)

    # Se houver autofix, salva spec corrigida
    if autofix_enabled:
        with open(spec_out, "w", encoding="utf-8") as f:
            json.dump(spec, f, indent=2, ensure_ascii=False)

    print(f"[OK] Validação concluída. Resultados em {report_file}. Spec corrigida em {spec_out}")


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