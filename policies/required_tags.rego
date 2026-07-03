# Example organization policy: newly created taggable resources must carry
# an Environment tag. Built-in rules cover universal risks; rules like this
# one are org-specific and belong to the policy team — see docs/rego.md.

package tfsentry

import rego.v1

taggable := {"aws_instance", "aws_s3_bucket", "aws_db_instance", "aws_ebs_volume"}

deny contains result if {
	some rc in input.resource_changes
	rc.mode == "managed"
	rc.type in taggable
	"create" in rc.change.actions
	not rc.change.after.tags.Environment

	result := {
		"msg": sprintf("%s: missing required tag 'Environment'", [rc.address]),
		"address": rc.address,
		"severity": "medium",
	}
}
