import json
import sys
from pathlib import Path

def extract_other_rules(input_file: str, output_file: str):
    # Load the original JSON
    with open(input_file, "r", encoding="utf-8") as f:
        rules = json.load(f)

    # Filter rules with op = OTHER
    other_rules = [r for r in rules if r.get("op") == "OTHER"]

    # Save to a new file
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(other_rules, f, ensure_ascii=False, indent=2)

    # Print details of each rule
    print(f"\n=== Found {len(other_rules)} rules with op=OTHER ===\n")
    for i, rule in enumerate(other_rules, start=1):
        print(f"Rule {i}:")
        print(json.dumps(rule, ensure_ascii=False, indent=2))
        print("-" * 60)

    print(f"\nFile saved to: {output_file}")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python extract_other_rules.py <rules.json> <other_rules.json>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    extract_other_rules(input_file, output_file)
