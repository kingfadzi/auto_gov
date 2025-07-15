package pipeline

default allow = false

allow if {
  input.validated_jira == true
  input.has_high_severity == false
  input.license_compliant == true
}
