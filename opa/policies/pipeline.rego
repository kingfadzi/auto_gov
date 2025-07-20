package pipeline

default allow = false

allow if {
    count(deny_reason) == 0
}

deny_reason contains reason if {
    some stage
    input[stage]
    reason := validate_stage(stage, input[stage])
    reason != ""
}

validate_stage(stage, stage_data) := reason if {
    # First check if metadata exists
    not stage_data.metadata
    reason := "missing metadata block"
} else := reason if {
    # Build stage validations
    stage == "build"
    not stage_data.metadata.license_compliant
    reason := "license non-compliance"
} else := reason if {
    stage == "build"
    count(stage_data.metadata.vulns.high) > 0
    reason := "high severity vulnerabilities present"
} else := reason if {
    # Test stage validations
    stage == "test"
    not stage_data.metadata.unit_tests_passed
    reason := "unit tests did not pass"
} else := reason if {
    stage == "test"
    not stage_data.metadata.coverage
    reason := "code coverage missing"
} else := reason if {
    stage == "test"
    stage_data.metadata.coverage < 80
    reason := "code coverage too low"
} else := reason if {
    # Validate stage validations
    stage == "validate"
    not stage_data.metadata.jira_ticket.validated
    reason := "Jira ticket validation failed"
} else := reason if {
    # Approval stage validations
    stage == "approval"
    not stage_data.metadata.change_request.approved
    reason := "Change Request not approved"
} else := ""