# Endpoint DLP Device Group Sync

PowerShell utility that identifies Microsoft Entra registered devices associated with users in a source security group and synchronizes those devices into a destination security group.

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

## Authentication Methods

### Device Code Authentication

Useful when interactive browser authentication is unavailable or not preferred.

Examples:
- Remote PowerShell sessions
- Environments where browser prompts are hidden
- Troubleshooting authentication issues
- Testing alternate authentication methods

### Interactive Browser Authentication

Recommended for normal administrative use.

Examples:
- Interactive desktop sessions
- Standard Microsoft Entra administration workflows
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

This is particularly important for Endpoint DLP deployments because those users may not be represented in device-scoped policies.

## Disclaimer

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.

IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY.
