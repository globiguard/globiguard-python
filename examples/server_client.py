import globiguard


client = globiguard.create_server_client(
    environment="sandbox",
    services={"controlPlane": "https://api.globiguard.com"},
    credential=globiguard.SecretCredential(
        project_id="proj_example",
        token="ggsk_example_replace_me",
        environment="sandbox",
    ),
)

decision = client.governed_actions.authorize_action_or_throw(
    {
        "actionType": "refund",
        "actor": {"id": "user_123"},
        "target": {"id": "order_456"},
        "reason": "Customer support refund approval",
    }
)

print(decision)

