package pipeline

default allow = false

allow if count(deny_reason) == 0

deny_reason[x] {
    some x
    input.stage == "validate"
    (not input.metadata.jira_ticket.validated) == true
    x := "Jira ticket validation failed"
}

deny_reason[x] {
    some x
    input.stage == "test"
    not input.metadata.unit_tests_passed
    x := "unit tests did not pass"
}

deny_reason[x] {
    some x
    input.stage == "test"
    not input.metadata.coverage
    x := "code coverage missing"
}

deny_reason[x] {
    some x
    input.stage == "test"
    input.metadata.coverage < 80
    x := "code coverage too low"
}

deny_reason[x] {
    some x
    input.stage == "build"
    count(input.metadata.vulns.high) > 0
    x := "high severity vulnerabilities present"
}

deny_reason[x] {
    some x
    input.stage == "scan"
    count(input.metadata.vulns.high) > 0
    x := "high severity vulnerabilities present"
}

deny_reason[x] {
    some x
    not input.metadata.license_compliant
    x := "license non-compliance"
}

deny_reason[x] {
    some x
    input.stage == "approval"
    not input.metadata.change_request.approved
    x := "Change Request not approved"
}

deny_reason[x] {
    some x
    not input.metadata
    x := "missing metadata block"
}
