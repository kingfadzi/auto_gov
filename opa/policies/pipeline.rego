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
    reasons := stage_deny_reasons(stage, input[stage])
    reason := reasons[_]
}

# Helper function to get deny reasons for a specific stage
stage_deny_reasons(stage, stage_input) := reasons if {
    reasons := [
        msg |
        msg := validate_stage(stage, stage_input)
        msg != ""
    ]
}

# Validation rules for each stage type
validate_stage(stage, stage_input) := msg if {
    stage == "validate"
    not stage_input.jira_ticket.validated
    msg := "Jira ticket validation failed"
}

validate_stage(stage, stage_input) := msg if {
    stage == "test"
    not stage_input.unit_tests_passed
    msg := "unit tests did not pass"
}

validate_stage(stage, stage_input) := msg if {
    stage == "test"
    not stage_input.coverage
    msg := "code coverage missing"
}

validate_stage(stage, stage_input) := msg if {
    stage == "test"
    stage_input.coverage < 80
    msg := "code coverage too low"
}

validate_stage(stage, stage_input) := msg if {
    stage == "build"
    count(stage_input.vulns.high) > 0
    msg := "high severity vulnerabilities present"
}

validate_stage(stage, stage_input) := msg if {
    stage == "scan"
    count(stage_input.vulns.high) > 0
    msg := "high severity vulnerabilities present"
}

validate_stage(stage, stage_input) := msg if {
    stage == "approval"
    not stage_input.change_request.approved
    msg := "Change Request not approved"
}

validate_stage(stage, stage_input) := msg if {
    not stage_input.license_compliant
    msg := "license non-compliance"
}

validate_stage(stage, stage_input) := msg if {
    not stage_input
    msg := "missing metadata block"
}

# Default case returns empty string when no issues found
validate_stage(_, _) := "" if {
    true
}