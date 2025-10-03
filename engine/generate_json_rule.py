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
# 1. Extrair regras do PDF
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

# -------------------------
# 3. Interpretar regra
# -------------------------
def interpret_rule(rule_text: str, spec_text: str, idx: int):
    prompt = f"""
    Você é um analisador de regras OpenAPI/Swagger.

    Sua tarefa é:
    1. Ler a regra abaixo.
    2. Extrair o código da regra (ex: R32, R58, R01).
    3. Classifique a regra em exatamente **um** dos seguintes tipos de operação:
       [ensure, unique, regex, value_regex, enum, length, uniform_all, update, OTHER]

    ⚠️ Como escolher corretamente:
    ### Instruções de como classificar `op`

    - ensure: usado quando a regra exige que um campo exista.  
      Exemplo: "Responses devem conter 200" → field="200".  
      Exemplo: "Toda resposta deve ter description" → field="description".  
      **Não inventar valores aleatórios (ex: ranges, -x). Apenas garantir a presença ou valor fixo.**

    - unique: usado quando a regra proíbe duplicação.  
      Exemplo: "operationId deve ser único".  

    - regex: usado para validar formato de nomes de atributos ou parâmetros.  
      Deve incluir "pattern".  
      Exemplo: "nomes devem estar em lowerCamelCase" → pattern="^[a-z][a-zA-Z0-9]*$".  

    - value_regex: usado para validar conteúdo de um valor string (URLs, padrões textuais).  
      Deve incluir "pattern" e, opcionalmente, "value" sugerido.  
      Exemplo: "url deve começar com http://Caminho_backend/" → pattern="^http://Caminho_backend/.*$".  

    - enum: usado para regras que restringem valores a um conjunto fixo.  
      Deve incluir "value" com lista de valores aceitos.  
      Exemplo: "type deve ser string, integer ou boolean".  

    - length: usado para validar tamanho de strings.  
      Deve incluir "value": {{"min": X, "max": Y}}.  
      Exemplo: "CPF deve ter exatamente 11 caracteres".  

    - uniform_all: usado quando a regra exige consistência entre definições repetidas.  
      Exemplo: "Campos com mesmo nome devem ter a mesma configuração".  

    - update: usado quando se torna necessário atualizar o nome de atributo ou parametro por outro
      Exemplo: "Endpoints devem estar no plural", "Trocar o nome do atributo", "Atualizar o atributo por"  

    - OTHER: se não se encaixar em nenhuma das categorias.  

    ⚠️ Campos adicionais:
    - Se a regra mencionar métodos HTTP específicos (GET, POST, PUT, PATCH, DELETE), inclua `"methods": ["get", "post", ...]`.
    - scope deve ser um entre: "responses", "parameters", "schema", "schema properties", "operations", "servers", "OTHER".
    - field deve ser o campo alvo ou "*" se genérico. Nunca gerar mais de um field
    - severity deve ser "error" ou "warning".
    - autofix sempre booleano.

    ⚠️ O campo `selector` deve ser **sempre compatível com a biblioteca jsonpath_ng** (JSONPath).
    - Sempre utilize a especificacão base para poder montar o selector
    ⚠️ Nunca utilize pontos com números de versão (ex: v3.0.1).  
    ⚠️ Nunca utilize campos concatenados com erro de digitação.  
    ⚠️ Nunca use aspas dentro de selectors.  
    - Gerar **sempre** um único selector
    
    ⚠️ Não use: colchetes com aspas, caminhos compostos (`"a.b"`), nomes de versão (`openapi.v3.0.1`) ou operadores inexistentes.
    Se a regra não permitir um JSONPath simples, use `"$.OTHER"`.

    ⚠️ REGRAS IMPORTANTES PARA O JSON FINAL:
    - Campos obrigatórios SEMPRE: 
      rule_code, summary, scope, op, selector, field, check_text, severity, hints, autofix
    - O campo `op` é **sempre obrigatório**. Se não souber qual usar, defina `op`: "OTHER"`.
    - Não deixe nenhum campo em branco ou faltando.
    - Se `op` = "regex" ou "value_regex", inclua também `pattern`.
    - Se `op` = "enum", inclua também `value` como lista de valores.
    - Se `op` = "length", inclua também `value` no formato {{"min": X, "max": Y}}.
    - Se `op` = "uniform_all", não há `pattern` ou `value`, apenas `check_text`.
    - Se `op` = "update", não há `pattern` apenas o campo `field` que deve conter o valor original a ser atualizado e o campo `value` que é **obrigatório** e deve conter o novo valor de substituição.

    ⚠️ Estilo:
    - O JSON deve estar em **português** nos campos textuais (summary, check_text, hints).
    - Nunca omita campos, mesmo que precise usar valores plausíveis.

    Exemplos válidos:

    - ensure:
    {{
      "rule_code": "R01",
      "summary": "Responses devem conter 200",
      "scope": "responses",
      "op": "ensure",
      "selector": "$.paths.*.*.responses",
      "field": "200",
      "check_text": "Todas as operações devem ter response 200",
      "severity": "error",
      "autofix": true,
      "hints": ["Adicione responses.200 com description"]
    }}

    - unique:
    {{
      "rule_code": "R07",
      "summary": "operationId deve ser único",
      "scope": "operations",
      "op": "unique",
      "selector": "$.paths.*.*",
      "field": "operationId",
      "check_text": "Cada operação deve ter operationId único",
      "severity": "error",
      "autofix": true,
      "hints": ["Renomeie operationIds duplicados"]
    }}

    - regex:
    {{
      "rule_code": "R52",
      "summary": "Parâmetros em lowerCamelCase",
      "scope": "parameters",
      "op": "regex",
      "selector": "$.paths.*.*.parameters[*].name",
      "pattern": "^[a-z][a-zA-Z0-9]*$",
      "field": "name",
      "check_text": "Parâmetros devem seguir lowerCamelCase",
      "severity": "warning",
      "autofix": true,
      "hints": ["Exemplo: investmentFundName"]
    }}

    - value_regex:
    {{
      "rule_code": "R52",
      "summary": "URLs devem começar com http://Caminho_backend/",
      "scope": "servers",
      "op": "value_regex",
      "selector": "$.servers[*].url",
      "pattern": "^http://Caminho_backend/.*$",
      "field": "url",
      "check_text": "O campo 'url' deve começar com 'http://Caminho_backend/'",
      "severity": "error",
      "autofix": true,
      "value": "http://Caminho_backend/api/fees/v2",
      "hints": ["Corrija o valor para iniciar com http://Caminho_backend/"]
    }}

    - enum:
    {{
      "rule_code": "R05",
      "summary": "Tipo deve estar no conjunto permitido",
      "scope": "schema properties",
      "op": "enum",
      "selector": "$.components.schemas.*.properties.*",
      "field": "type",
      "value": ["string", "integer", "boolean", "number"],
      "check_text": "Tipos devem estar no conjunto permitido",
      "severity": "error",
      "autofix": true,
      "hints": ["Verifique se 'type' segue o padrão JSON Schema"]
    }}

    - length:
    {{
      "rule_code": "R11",
      "summary": "CPF deve ter 11 caracteres",
      "scope": "schema properties",
      "op": "length",
      "selector": "$.components.schemas.*.properties",
      "field": "*cpf*",
      "value": {{"min": 11, "max": 11}},
      "check_text": "Qualquer campo que contenha 'cpf' no nome deve ter exatamente 11 caracteres",
      "severity": "error",
      "autofix": true,
      "hints": ["Defina minLength=11 e maxLength=11"]
    }}

    - uniform_all:
    {{
      "rule_code": "R58",
      "summary": "Propriedades com mesmo nome devem ter definição uniforme",
      "scope": "schema+parameters",
      "op": "uniform_all",
      "selector": "$.components.schemas.*.properties",
      "field": "*",
      "check_text": "Campos iguais em diferentes locais devem ter os mesmos atributos",
      "severity": "error",
      "autofix": true,
      "hints": ["Exemplo: managerDocumentNumber deve ter sempre {{type=string, maxLength=14}}"]
    }}

    - update:
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
    "hints": ["Use nomes de recursos sempre no plural"]
    }}
      
    Regra {idx}:
    {rule_text}

    Especificação Base:
    {spec_text}

    Responda apenas com JSON válido.
    """

    response = llm.invoke(prompt)

    raw = response.content.strip()

    # print(f"\n--- Resposta crua da LLM para regra {idx} ---")
    # print(raw)
    # print("--------------------------------------------")

    if not raw:
        raise ValueError(f"Resposta vazia da LLM para regra {idx}")

    # Extrair apenas o JSON
    start = raw.find("{")
    end = raw.rfind("}") + 1
    if start == -1 or end == -1:
        # raise ValueError(f"Nenhum JSON encontrado (regra {idx})")
        return {
            "rule_code": f"R_FAIL_{idx}",
            "summary": "Falha ao interpretar",
            "scope": "OTHER",
            "op": "OTHER",
            "selector": "$",
            "field": "*",
            "check_text": "Erro ao decodificar regra",
            "severity": "error",
            "hints": ["Revisar manualmente"],
            "autofix": False
        }

    raw_json = raw[start:end]

    def sanitize(text: str) -> str:
        text = text.replace("'", '"')  # força aspas duplas
        text = re.sub(r",(\s*[}\]])", r"\1", text)  # remove vírgula sobrando
        text = text.replace("\\", "\\\\")  # corrige escapes
        return text

    try:
        rule_obj = json.loads(raw_json)
        rule_obj["oas_version"] = detect_oas_version(rule_text)
        return rule_obj
    except json.JSONDecodeError:
        print(f"⚠️ JSON inválido na regra {idx}, tentando corrigir...")
        safe = sanitize(raw_json)
        try:
            rule_obj = json.loads(safe)
            rule_obj["oas_version"] = detect_oas_version(rule_text)
            return rule_obj
        except json.JSONDecodeError as e:
            print(f"❌ Falha ao corrigir JSON da regra {idx}: {e}")
            return {
                "rule_code": f"R_FAIL_{idx}",
                "oas_version": None,
                "summary": "Falha ao interpretar",
                "scope": "OTHER",
                "op": "OTHER",
                "selector": "$",
                "field": "*",
                "check_text": "Erro ao decodificar regra",
                "severity": "error",
                "hints": ["Revisar manualmente"],
                "autofix": False
            }

# -------------------------
# 4. Orquestrar pipeline
# -------------------------
def process_pdf_with_llm(pdf_file: str, spec_text: str, output_file="rules.json"):
    rules_texts = extract_rules_from_pdf(pdf_file)
    results = []

    for idx, rule_text in enumerate(tqdm(rules_texts, desc="Processando regras"), start=1):
        rule_json = interpret_rule(rule_text, spec_text, idx)
        results.append(rule_json)

        # imprime na tela a regra e o json correspondente
        print("\n📌 Regra encontrada:")
        print(rule_text)
        print("➡️ JSON gerado:")
        print(json.dumps(rule_json, indent=2, ensure_ascii=False))

    Path(output_file).write_text(
        json.dumps(results, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )
    print(f"\n✅ {len(results)} regras exportadas → {output_file}")


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