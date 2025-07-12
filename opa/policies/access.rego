package access

default allow = false

allow if input.user == "admin"
