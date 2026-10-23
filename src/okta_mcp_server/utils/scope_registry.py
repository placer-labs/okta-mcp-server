# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2025-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""OAuth 2.0 scope registry for the Okta MCP Server.

``TOOL_SCOPE_REGISTRY`` maps every MCP tool name to the minimum Okta OAuth 2.0
scope required to call it. ``scope_guard.prune_tools_by_scope`` uses it to hide
tools whose scope is not configured, and a test asserts every registered tool
has an entry.

Scope naming convention:
    ``okta.<resource>.read``    — GET operations (read-only).
    ``okta.<resource>.manage``  — POST / PUT / DELETE operations (write).
    A configured ``*.manage`` scope also satisfies ``*.read`` for the same resource.

Reference: https://developer.okta.com/docs/api/oauth2
"""

TOOL_SCOPE_REGISTRY: dict[str, str] = {
    # Users
    "list_users": "okta.users.read",
    "get_user": "okta.users.read",
    "get_user_profile_attributes": "okta.users.read",
    "list_user_groups": "okta.users.read",
    "create_user": "okta.users.manage",
    "update_user": "okta.users.manage",
    "deactivate_user": "okta.users.manage",
    "delete_deactivated_user": "okta.users.manage",
    # Groups
    "list_groups": "okta.groups.read",
    "get_group": "okta.groups.read",
    "list_group_users": "okta.groups.read",
    "list_group_apps": "okta.groups.read",
    "create_group": "okta.groups.manage",
    "update_group": "okta.groups.manage",
    "delete_group": "okta.groups.manage",
    "confirm_delete_group": "okta.groups.manage",
    "add_user_to_group": "okta.groups.manage",
    "remove_user_from_group": "okta.groups.manage",
    # Group rules
    "list_group_rules": "okta.groups.read",
    "get_group_rule": "okta.groups.read",
    # Applications
    "list_applications": "okta.apps.read",
    "get_application": "okta.apps.read",
    "list_group_push_mappings": "okta.apps.read",
    "create_application": "okta.apps.manage",
    "update_application": "okta.apps.manage",
    "delete_application": "okta.apps.manage",
    "confirm_delete_application": "okta.apps.manage",
    "activate_application": "okta.apps.manage",
    "deactivate_application": "okta.apps.manage",
    # Policies
    "list_policies": "okta.policies.read",
    "get_policy": "okta.policies.read",
    "list_policy_rules": "okta.policies.read",
    "get_policy_rule": "okta.policies.read",
    "create_policy": "okta.policies.manage",
    "update_policy": "okta.policies.manage",
    "delete_policy": "okta.policies.manage",
    "activate_policy": "okta.policies.manage",
    "deactivate_policy": "okta.policies.manage",
    "create_policy_rule": "okta.policies.manage",
    "update_policy_rule": "okta.policies.manage",
    "delete_policy_rule": "okta.policies.manage",
    "activate_policy_rule": "okta.policies.manage",
    "deactivate_policy_rule": "okta.policies.manage",
    # Device assurance
    "list_device_assurance_policies": "okta.deviceAssurance.read",
    "get_device_assurance_policy": "okta.deviceAssurance.read",
    "create_device_assurance_policy": "okta.deviceAssurance.manage",
    "replace_device_assurance_policy": "okta.deviceAssurance.manage",
    "delete_device_assurance_policy": "okta.deviceAssurance.manage",
    "confirm_delete_device_assurance_policy": "okta.deviceAssurance.manage",
    # System logs
    "get_logs": "okta.logs.read",
    "get_login_failures": "okta.logs.read",
}
