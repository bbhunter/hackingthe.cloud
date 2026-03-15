---
author_name: Raajhesh Kannaa Chidambaram
title: Detect Public Resource Exposure via Session Policy Error Messages
description: Use session policy denials and verbose IAM error messages to determine if AWS resources have public resource-based policies.
---

<div class="grid cards" markdown>

-   :material-account:{ .lg .middle } __Original Research__

    ---

    [Don't Expose Yourself in Public, Let AWS Error Messages Do It](https://www.plerion.com/blog/dont-expose-yourself-in-public-let-aws-error-messages-do-it) by Daniel Grzelak and Sam Cox

-   :material-tools:{ .lg .middle } __Tools mentioned in this article__

    ---

    [sns-buster](https://github.com/plerionhq/sns-buster): Test SNS topic exposure across 14 actions.

</div>

AWS has been expanding [verbose IAM error messages](https://docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot_access-denied.html) that include a "because" clause identifying which policy layer blocked a request. In [January 2026](https://aws.amazon.com/about-aws/whats-new/2026/01/additional-policy-details-access-denied-error/), this was extended to include policy ARNs. This created a reconnaissance primitive: by combining a deny-all [session policy](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html#policies_session) with API calls against resources using `Principal: *` policies, you can determine whether a target resource is publicly accessible.

## How It Works

When a resource-based policy grants access to `Principal: *` (public), that grant is evaluated independently from session policy restrictions. A deny-all session policy will still block the request, but the [verbose error message](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html) reveals that the session policy was the blocker, not the resource policy. This tells you the resource would have been accessible without the session policy constraint:

| Error Message Contains | Meaning | Classification |
|---|---|---|
| "deny in a session policy" | Resource-based policy allowed access, but session policy blocked it | **PUBLIC** |
| "deny in a resource-based policy" | Resource explicitly denied access | **PRIVATE** |
| "no resource-based policy allows" | Resource-based policy implicitly denied (no matching allow statement) | **NOT PUBLIC** |
| "no identity-based policy allows" | No public access granted (resource may not exist, or its policy does not grant access to the caller) | **NOT PUBLIC** |

The key insight: if AWS reports the session policy as the reason for denial, the resource-based policy would have allowed the request. This is strong empirical evidence that the resource is publicly accessible. Note that when multiple policy types deny a request, AWS reports only one of them, so treat this as an observed heuristic rather than a formal IAM guarantee.

## Setup

Create a role in your own account with a simple trust policy:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": { "AWS": "arn:aws:iam::ACCOUNT_ID:root" },
            "Action": "sts:AssumeRole"
        }
    ]
}
```

```bash
aws iam create-role --role-name exposure-test \
  --assume-role-policy-document file://trust-policy.json
```

Then assume it with a deny-all session policy:

```bash
aws sts assume-role \
  --role-arn arn:aws:iam::$ACCOUNT_ID:role/exposure-test \
  --role-session-name probe \
  --policy '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}'
```

Export the returned temporary credentials and use them for all subsequent probe calls.

## Example: Testing an SQS Queue

```bash
aws sqs get-queue-attributes \
  --queue-url "https://sqs.us-east-1.amazonaws.com/TARGET_ACCOUNT/queue-name" \
  --attribute-names All \
  --region us-east-1 2>&1
```

If the queue has a public policy, the error will contain `"explicit deny in a session policy"`. If the queue is private, you will see `"explicit deny in a resource-based policy"`, `"no resource-based policy allows"`, or `"no identity-based policy allows"`.

## Supported Services

This technique works with any service that supports resource-based policies and returns verbose error messages. Confirmed services include:

- **SNS** (GetTopicAttributes, Publish, Subscribe, and others)
- **SQS** (GetQueueAttributes, SendMessage)
- **Lambda** (GetFunction, InvokeFunction)
- **KMS** (DescribeKey, Encrypt, Decrypt)
- **ECR** (GetRepositoryPolicy, BatchGetImage)
- **EventBridge** (PutEvents, DescribeEventBus)

!!! note
    S3 returns enhanced error context for same-account and same-organization requests, but cross-account requests outside your organization still return a generic `Access Denied`. For cross-org S3 enumeration, use different techniques.

## Limitations

- **SCP/RCP interference.** If the target account's organization has Service Control Policies or Resource Control Policies that deny the action, those evaluate first and mask the resource policy result. Most production AWS accounts have SCPs, so expect false negatives.
- **Ambiguous negatives.** The `"no identity-based policy allows"` response does not distinguish between a resource that does not exist, one with no resource-based policy, and one with a private policy that does not grant access to the caller.
- **Service coverage.** Not all AWS services have adopted the verbose error format yet. Test before relying on this for a specific service.
- **Cross-account scope.** AWS documentation states that enhanced error messages are available for single-account and same-organization scenarios. This technique works because the session policy denial is evaluated in the caller's own context, but verify the verbose error format is returned for your specific target before relying on the results.

## OPSEC Considerations

Session policy denials are evaluated in the caller's context. For the services listed above, CloudTrail logs for the denied call appear only in **your** account, not the target's. This has been empirically verified for SNS and SQS, though behavior may vary for other services. Regardless, it is significantly stealthier than alternatives that require direct interaction with the target resource.

The deny-all session policy is also universal. One set of credentials works across all services and actions, with no need for action-specific probes or mutations.
