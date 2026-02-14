package devsecops.gate

default decision = {"result": "pass", "reasons": ["no_open_risks"]}

decision := {"result": "warn", "reasons": reasons} if {
  risky := [f | f := input.findings[_]; f.status == "open"; f.severity == "critical" or f.severity == "high" or f.severity == "medium"]
  count(risky) > 0
  reasons := ["warn_only_mode_active", sprintf("open_findings:%v", [count(risky)])]
}
