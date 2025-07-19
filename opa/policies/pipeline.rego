package pipeline

default allow = false

# Known stages
stages := {"build", "test", "validate", "scan", "approval"}

# Collect all deny reasons across available stage inputs
deny_reason[reason] if {
  some s
  stages[s]
  input[s]
  reason := validate(s, input[s])
  reason != ""
}

# Allow if no deny reasons
allow if {
  count(deny_reason) == 0
}

# All per-stage validations return a single string ("" if no issue)
validate(stage, sinput) = msg if {
  stage == "validate"
  not sinput.jira_ticket.validated
  msg := "Jira ticket validation failed"
}

validate(stage, sinput) = msg if {
  stage == "test"
  not sinput.unit_tests_passed
  msg := "unit tests did not pass"
}

validate(stage, sinput) = msg if {
  stage == "test"
  not sinput.coverage
  msg := "code coverage missing"
}

validate(stage, sinput) = msg if {
  stage == "test"
  sinput.coverage < 80
  msg := "code coverage too low"
}

validate(stage, sinput) = msg if {
  stage == "build"
  count(sinput.vulns.high) > 0
  msg := "high severity vulnerabilities present"
}

validate(stage, sinput) = msg if {
  stage == "scan"
  count(sinput.vulns.high) > 0
  msg := "high severity vulnerabilities present"
}

validate(stage, sinput) = msg if {
  stage == "approval"
  not sinput.change_request.approved
  msg := "Change Request not approved"
}

validate(stage, sinput) = msg if {
  not sinput.license_compliant
  msg := "license non-compliance"
}

validate(stage, sinput) = msg if {
  not sinput
  msg := "missing metadata block"
}

# Fallback for no match — return empty string
validate(_, _) = "" if {
  true
}
