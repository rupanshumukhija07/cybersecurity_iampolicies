import json
import datetime
import boto3

config = boto3.client("config")


def lambda_handler(event, context):
    """
    Entry point for AWS Config custom rule.
    Expects standard Config `invokingEvent` and `resultToken` in `event`.
    """

    # Parse invokingEvent from AWS Config
    invoking_event = json.loads(event["invokingEvent"])
    configuration_item = invoking_event.get("configurationItem")

    # If we don't have a valid configuration item, mark NOT_APPLICABLE
    if not configuration_item or configuration_item.get("configurationItemStatus") == "ResourceDeleted":
        return put_evaluation(
            resource_id=configuration_item["resourceId"] if configuration_item else "UNKNOWN",
            resource_type=configuration_item["resourceType"] if configuration_item else "AWS::IAM::Policy",
            compliance_type="NOT_APPLICABLE",
            result_token=event["resultToken"]
        )

    resource_id = configuration_item["resourceId"]
    resource_type = configuration_item["resourceType"]

    # Extract the IAM policy document
    policy_document = configuration_item.get("configuration", {}).get("policyDocument")
    if policy_document is None:
        # No policy document found → not applicable
        return put_evaluation(
            resource_id=resource_id,
            resource_type=resource_type,
            compliance_type="NOT_APPLICABLE",
            result_token=event["resultToken"]
        )

    # policyDocument can be string or dict depending on how Config sends it
    if isinstance(policy_document, str):
        policy_document = json.loads(policy_document)

    statements = policy_document.get("Statement", [])
    if isinstance(statements, dict):
        # Normalize single statement object to list
        statements = [statements]

    non_compliant = False

    for stmt in statements:
        effect = stmt.get("Effect")
        action = stmt.get("Action")
        resource = stmt.get("Resource")

        # Normalize Action/Resource to lists
        if isinstance(action, str):
            actions = [action]
        else:
            actions = action or []

        if isinstance(resource, str):
            resources = [resource]
        else:
            resources = resource or []

        # Capital One style pattern: Allow + Action:* + Resource:*
        if effect == "Allow" and "*" in actions and "*" in resources:
            non_compliant = True
            break

    compliance_type = "NON_COMPLIANT" if non_compliant else "COMPLIANT"

    return put_evaluation(
        resource_id=resource_id,
        resource_type=resource_type,
        compliance_type=compliance_type,
        result_token=event["resultToken"]
    )


def put_evaluation(resource_id, resource_type, compliance_type, result_token):
    """
    Helper to call AWS Config put_evaluations.
    """
    evaluation = {
        "ComplianceResourceId": resource_id,
        "ComplianceResourceType": resource_type,
        "ComplianceType": compliance_type,
        "OrderingTimestamp": datetime.datetime.utcnow()
    }

    response = config.put_evaluations(
        Evaluations=[evaluation],
        ResultToken=result_token
    )

    return response