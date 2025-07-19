package pipeline

default allow = false

# Top-level allow
allow if count(deny_reason) == 0

deny_reason[x] if x == "Jira ticket validation failed" {
  input.stage == "validate"
  not input.metadata.jira_ticket.validated
}

deny_reason[x] if x == "unit tests did not pass" {
  input.stage == "test"
  not input.metadata.unit_tests_passed
}

deny_reason[x] if x == "code coverage missing or too low" {
  input.stage == "test"
  not input.metadata.coverage
} {
  input.stage == "test"
  input.metadata.coverage < 80
}

deny_reason[x] if x == "high severity vulnerabilities present" {
  input.stage == "build"
  input.metadata.vulns.high > 0
} {
  input.stage == "scan"
  input.metadata.vulns.high > 0
}

deny_reason[x] if x == "license non-compliance" {
  not input.metadata.license_compliant
}

deny_reason[x] if x == "Change Request not approved" {
  input.stage == "approval"
  not input.metadata.change_request.approved
}

deny_reason[x] if x == "missing metadata block" {
  not input.metadata
}
