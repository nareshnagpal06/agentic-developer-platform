"""Cedar policy generation — the enforcement control.

One policy per tool, fencing it to its ADP org (custom:org_id). This is the only
control that actually gates tool access; the registry does not.
"""
