package pipeline

default allow = false

# Top-level rule
allow {
  not deny_reason[_]
}

########## Validation Stage ##########

deny_reason["Jira ticket validation failed"] {
  input.stage == "validate"
  not input.metadata.jira_ticket.validated
}

########## Test Stage ##########

deny_reason["unit tests did not pass"] {
  input.stage == "test"
  not input.metadata.unit_tests_passed
}

deny_reason["code coverage missing or too low"] {
  input.stage == "test"
  not input.metadata.coverage
} {
  input.stage == "test"
  input.metadata.coverage < 80
}

########## Build or Scan Stage ##########

deny_reason["high severity vulnerabilities present"] {
  input.stage == "build"
  input.metadata.vulns.high > 0
} {
  input.stage == "scan"
  input.metadata.vulns.high > 0
}

########## License Check ##########

deny_reason["license non-compliance"] {
  not input.metadata.license_compliant
}

########## Approval Stage ##########

deny_reason["Change Request not approved"] {
  input.stage == "approval"
  not input.metadata.change_request.approved
}

########## Missing Metadata ##########

deny_reason["missing metadata block"] {
  not input.metadata
}
