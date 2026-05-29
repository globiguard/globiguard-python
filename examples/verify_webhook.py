import globiguard


def handle_webhook(headers, raw_body: bytes) -> dict:
    result = globiguard.verify_trust_webhook(
        headers=headers,
        raw_body=raw_body,
        signing_secret="whsec_example_replace_me",
    )
    if not result["ok"]:
        raise ValueError(result["error"]["message"])
    return result["envelope"]

