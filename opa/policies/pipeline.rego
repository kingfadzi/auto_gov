package pipeline

# Known pipeline stages in sequence
all_stages := ["validate", "build", "test", "scan", "approval", "deploy"]
required_stages := {"validate", "build", "test", "scan", "approval"}

default allow = false

# Main decision - allow if no deny reasons found
allow if {
    count(deny_reason) == 0
}

# Collect all deny reasons
deny_reason contains reason if {
    some stage
    input[stage]
    reason := validate_stage(stage, input[stage])
    reason != ""
}

# Special handling for deploy stage - require all previous stages
deny_reason contains reason if {
    input.deploy
    missing_stage := required_stages[_]
    not input[missing_stage]
    reason := sprintf("Missing required stage: %s", [missing_stage])
}

# Stage validation function
validate_stage(stage, stage_data) := reason if {
    # First check if metadata exists
    not stage_data.metadata
    reason := "missing metadata block"
} else := reason if {
    # Validate stage
    stage == "validate"
    not stage_data.metadata.jira_ticket.validated
    reason := "Jira ticket validation failed"
} else := reason if {
    # Build stage
    stage == "build"
    not stage_data.metadata.license_compliant
    reason := "license non-compliance"
} else := reason if {
    stage == "build"
    count(stage_data.metadata.vulns.high) > 0
    reason := "high severity vulnerabilities present"
} else := reason if {
    # Test stage
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
    # Scan stage
    stage == "scan"
    count(stage_data.metadata.vulns.high) > 0
    reason := "high severity vulnerabilities present"
} else := reason if {
    # Approval stage
    stage == "approval"
    not stage_data.metadata.change_request.approved
    reason := "Change Request not approved"
} else := ""