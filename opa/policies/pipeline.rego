package pipeline

stages := {"build", "test", "validate", "scan", "approval"}

default allow = false

allow if {
    count(deny_reason) == 0
}

deny_reason contains reason if {
    some stage
    stages[stage]
    input[stage]
    reason := stage_deny_reason(stage, input[stage])
    reason != ""
}

stage_deny_reason(stage, stage_input) := reason if {
    # Check for missing metadata first
    not stage_input.predicate.metadata
    reason := "missing metadata block"
} else := reason if {
    # Stage-specific validations
    stage == "validate"
    not stage_input.predicate.metadata.jira_ticket.validated
    reason := "Jira ticket validation failed"
} else := reason if {
    stage == "test"
    not stage_input.predicate.metadata.unit_tests_passed
    reason := "unit tests did not pass"
} else := reason if {
    stage == "test"
    not stage_input.predicate.metadata.coverage
    reason := "code coverage missing"
} else := reason if {
    stage == "test"
    stage_input.predicate.metadata.coverage < 80
    reason := "code coverage too low"
} else := reason if {
    stage == "build"
    count(stage_input.predicate.metadata.vulns.high) > 0
    reason := "high severity vulnerabilities present"
} else := reason if {
    stage == "scan"
    count(stage_input.predicate.metadata.vulns.high) > 0
    reason := "high severity vulnerabilities present"
} else := reason if {
    stage == "approval"
    not stage_input.predicate.metadata.change_request.approved
    reason := "Change Request not approved"
} else := reason if {
    # License check - now properly scoped to metadata
    not stage_input.predicate.metadata.license_compliant
    reason := "license non-compliance"
} else := ""