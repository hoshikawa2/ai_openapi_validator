# 📘 Manual and Tutorial – OpenAPI Validation Tool

## 1. Introduction
(... same as before ...)

## 9. Additional Procedures and Tools
(... same as before ...)

---

## 10. Why LLM is Needed for Semantic Rules (Plural Example)

Deterministic approaches (like JSONPath, regex, enum) are **excellent for structural validations** (e.g., checking if a field exists, ensuring camelCase, verifying maxLength).  

However, some problems are **semantic**, not structural. For example:

- A path `/investment-fund` should ideally be `/investment-funds`.  
- Regex or JSONPath **cannot know** whether a resource name should be singular or plural.  
- Business context dictates this: endpoints typically represent **collections of resources** (plural).  

👉 This is why **LLM-based rules are required**. They can **interpret natural language and semantic context** to suggest corrections that deterministic code cannot handle.

### Example Rule (LLM Plural)

```json
{
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
  "hints": ["Always use resource names in plural"],
  "oas_version": null
}
```

### Why Deterministic Code Fails Here

- **Regex**: Can only match patterns (e.g., lowercase letters, underscores). It **cannot decide** if a word is plural or singular.  
- **Enum/Ensure**: Can check against fixed sets, but we cannot predefine **all valid plural forms** (funds, accounts, customers).  
- **JSONPath**: Can locate fields but not decide if naming is correct.  

Thus, a **deterministic-only validator cannot enforce plural rules**.

### LLM Prompt Example

The validator sends the **spec** and the **atomic rule** to the LLM with a deterministic instruction:

```text
RETURN **only** the OpenAPI SPECIFICATION in JSON, already corrected according to the received rule.  
If the rule does not apply or there is ambiguity, RETURN **exactly** the unchanged spec_json.  
DO NOT include markdown, comments, helper keys, or diffs.  

You will receive:
- ONE atomic rule in JSON (rule_json)
- ONE OpenAPI specification in JSON (spec_json)

Your task:
1) **Interpret** rule_json, including semantic hints such as plural vs singular.  
2) **Inspect** spec_json to find endpoints not aligned with plural naming.  
3) **Apply** the correction by updating singular endpoints to plural.  
```

### Dispatcher Code Comment

```python
if rule["rule_code"].startswith("LLM"):
    # 🚀 Semantic case: requires LLM interpretation
    # Example: Plural vs singular in endpoints (/investment-fund → /investment-funds)
    # Deterministic code cannot infer semantic correctness of words,
    # so we forward the spec and rule_json to the LLM prompt engine.
    corrected_spec = call_llm_with_rule(rule, spec)
else:
    # ✅ Deterministic case: handled by regex/ensure/enum/length
    corrected_spec = apply_deterministic_rule(rule, spec)
```

👉 With this approach, **deterministic rules** guarantee structural integrity, while **LLM rules** handle semantic corrections, making the validator complete and hybrid.

---

# ✅ Conclusion

This manual covers:
- Business problems solved by the tool.  
- Hybrid architecture with deterministic rules + LLM support.  
- Components (`generate_json_rule.py`, `rules_dispatcher.py`, `validate_selector.py`, `extract_OTHER_rules.py`).  
- JSON structure of rules and examples.  
- Step-by-step execution and validation.  
- Why **LLM is essential** for semantic cases like pluralization.  

👉 With these, you can automate validation and correction of OpenAPI specifications in a standardized way, with governance and flexibility.

## Acknowledgments

- **Author** - Cristiano Hoshikawa (Oracle LAD A-Team Solution Engineer)
