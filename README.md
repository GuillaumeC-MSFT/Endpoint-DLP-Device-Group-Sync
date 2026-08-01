# User-to-Device Group Sync for Microsoft Entra ID

PowerShell utility that identifies Microsoft Entra registered devices associated with users in a source security group and synchronizes those devices into a destination device security group.


The script supports interactive and automated execution scenarios, multiple authentication methods, validation checks, reporting, logging, and retry handling for Microsoft Graph operations.

## Features

- Interactive menu-driven experience
- Device Code, Interactive Browser, and Certificate-based authentication options
- Microsoft Graph module validation
- Source user group validation with pause-and-resume workflow
- Destination group validation and optional creation
- Retry logic for Microsoft Graph operations
- User-to-device relationship discovery
- CSV reporting and detailed logging
- Identification of users with no associated devices
- Accessible console messaging

 ## Use Cases

- Building device security groups from user security groups
- Validating user-to-device relationships in Microsoft Entra ID
- Identifying users without registered devices
- Maintaining device group memberships
- Device deployment readiness reviews
- Endpoint DLP deployment planning and validation
- Device-scoped Conditional Access planning

This script:

1. Reads users from a source security group.
2. Retrieves registered devices associated with those users.
3. Adds the devices into a destination device security group.
4. Produces reports highlighting users without associated devices.

## Requirements

- Windows PowerShell 5.1 or PowerShell 7+
- Microsoft Graph PowerShell SDK
- Microsoft Entra ID permissions required by the script

Required permissions:

- User.Read.All
- Device.Read.All
- Group.Read.All
- Group.ReadWrite.All
- GroupMember.Read.All
- GroupMember.ReadWrite.All

## Source Group Validation

The script requires the source user group to exist and contain at least one user.

If the group is missing or empty, the script will:

- Pause execution
- Display guidance to the operator
- Allow the group to be created or populated
- Re-prompt for the group name
- Resume validation without restarting the script

## Authentication Methods

### Device Code Authentication

Useful when interactive browser authentication is unavailable or not preferred.

Examples:
- Remote or restricted PowerShell environments
- Troubleshooting authentication issues
- Testing alternate authentication methods
- Situations where browser-based sign-in is not practical

### Interactive Browser Authentication

Recommended for normal administrative use.

Examples:
- Day-to-day Microsoft Entra administration
- Interactive desktop sessions
- Environments where browser-based authentication is permitted

### Certificate Authentication

Intended for unattended or automated execution scenarios.

Examples:
- Scheduled tasks
- Service accounts
- Automation platforms
- Operational runbooks

## Reports Generated

### Main Report

Contains:

- User
- Device
- Device ownership
- Planned action
- Result

### Users Without Devices Report

Highlights users that do not have an associated registered device.

This is particularly useful when planning Endpoint DLP or other device-scoped solutions because users without associated devices may not be represented in device-targeted policies.

## Disclaimer

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.

IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY.
