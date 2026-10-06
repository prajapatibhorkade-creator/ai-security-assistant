try:
    from app.threat_intel.extractor import extract_indicators
    from app.threat_intel.service import enrich_indicators
except ModuleNotFoundError:
    from backend.app.threat_intel.extractor import extract_indicators
    from backend.app.threat_intel.service import enrich_indicators


def main():
    log_text = """
Failed login detected from 192.168.1.50.
Requested domain example.com.
File hash:
0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
"""

    indicators = extract_indicators(log_text)

    print("\n=== EXTRACTED INDICATORS ===")

    for indicator in indicators:
        print(indicator)

    results = enrich_indicators(indicators)

    print("\n=== THREAT INTELLIGENCE ===")

    for result in results:
        print(result)


if __name__ == "__main__":
    main()