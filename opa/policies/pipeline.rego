package pipeline

# Known pipeline stages we want to evaluate
stages := {"build", "test", "validate", "scan", "approval"}

default allow = false

# Main decision - allow if no deny reasons found
allow if {
    count(deny_reason) == 0
}

# Deny reasons will be collected in this set
deny_reason contains reason if {
    some stage
    stages[stage]
    input[stage]
    reason := stage_deny_reason(stage, input[stage])
    reason != ""
}

# Single validation result per stage (avoids conflicts)
stage_deny_reason(stage, stage_input) := reason if {
    reason := validate_license(stage_input)
    reason != ""
} else := reason if {
    reason := validate_metadata(stage_input)
    reason != ""
} else := reason if {
    stage == "validate"
    reason := validate_jira_ticket(stage_input)
    reason != ""
} else := reason if {
    stage == "test"
    reason := validate_tests(stage_input)
    reason != ""
} else := reason if {
    stage == "test"
    reason := validate_coverage(stage_input)
    reason != ""
} else := reason if {
    stage == "build"
    reason := validate_vulns(stage_input)
    reason != ""
} else := reason if {
    stage == "scan"
    reason := validate_vulns(stage_input)
    reason != ""
} else := reason if {
    stage == "approval"
    reason := validate_approval(stage_input)
    reason != ""
} else := ""

# Individual validation functions
validate_jira_ticket(stage_input) := "Jira ticket validation failed" if {
    not stage_input.jira_ticket.validated
} else := ""

validate_tests(stage_input) := "unit tests did not pass" if {
    not stage_input.unit_tests_passed
} else := ""

validate_coverage(stage_input) := "code coverage missing" if {
    not stage_input.coverage
} else := "code coverage too low" if {
    stage_input.coverage < 80
} else := ""

validate_vulns(stage_input) := "high severity vulnerabilities present" if {
    count(stage_input.vulns.high) > 0
} else := ""

validate_approval(stage_input) := "Change Request not approved" if {
    not stage_input.change_request.approved
} else := ""

validate_license(stage_input) := "license non-compliance" if {
    not stage_input.license_compliant
} else := ""

validate_metadata(stage_input) := "missing metadata block" if {
    not stage_input
} else := ""