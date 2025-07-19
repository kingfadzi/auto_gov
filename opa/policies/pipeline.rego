package pipeline

default allow = false

allow {
    count(deny_reason) == 0
}

# -- DENY RULES (partial sets with predicates only)
deny_reason["Jira ticket validation failed"] {
    input.stage == "validate"
    not input.metadata.jira_ticket.validated
}

deny_reason["unit tests did not pass"] {
    input.stage == "test"
    not input.metadata.unit_tests_passed
}

deny_reason["code coverage missing"] {
    input.stage == "test"
    not input.metadata.coverage
}

deny_reason["code coverage too low"] {
    input.stage == "test"
    input.metadata.coverage
    input.metadata.coverage < 80
}

deny_reason["high severity vulnerabilities present"] {
    input.stage == "build"
    input.metadata.vulns.high
    input.metadata.vulns.high > 0
}

deny_reason["high severity vulnerabilities present"] {
    input.stage == "scan"
    input.metadata.vulns.high
    input.metadata.vulns.high > 0
}

deny_reason["license non-compliance"] {
    not input.metadata.license_compliant
}

deny_reason["Change Request not approved"] {
    input.stage == "approval"
    not input.metadata.change_request.approved
}

deny_reason["missing metadata block"] {
    not input.metadata
}
