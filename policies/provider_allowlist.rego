# Example organization policy: only approved providers may manage
# resources. Catches a PR that quietly introduces a new provider.

package tf_risk_review

import rego.v1

approved_providers := {
	"registry.terraform.io/hashicorp/aws",
	"registry.terraform.io/hashicorp/random",
	"registry.terraform.io/hashicorp/tls",
}

deny contains result if {
	some rc in input.resource_changes
	rc.mode == "managed"
	not rc.provider_name in approved_providers

	result := {
		"msg": sprintf("%s: provider %s is not on the approved list", [rc.address, rc.provider_name]),
		"address": rc.address,
		"severity": "high",
	}
}
