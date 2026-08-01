# Endpoint DLP Device Group Sync

PowerShell utility designed to help Endpoint DLP deployments by automatically identifying devices associated with users in a Microsoft Entra security group and synchronizing those devices into a device security group.

## Features

- Interactive menu
- Device Code Authentication
- Interactive Browser Authentication
- App-only Certificate Authentication
- Microsoft Graph module validation
- Automatic Microsoft Graph installation guidance
- Source group validation
- Pause/Resume workflow when source group is missing
- Re-prompt source group name after retry
- Destination device group creation
- Entra ID replication wait logic
- Membership retry logic
- Report Only mode
- Apply mode
- UsersWithoutDevices exception reporting
- Endpoint DLP coverage validation
- CSV reporting
- Detailed logging
- Accessibility-friendly console output

## Use Case

A common Endpoint DLP deployment challenge is ensuring that device-scoped policies have the correct device memberships.

This script:

1. Reads users from a source security group.
2. Retrieves registered devices associated with those users.
3. Adds the devices into a destination device security group.
4. Produces reports highlighting users without associated devices.

## Prerequisites

- PowerShell 5.1 or PowerShell 7+
- Microsoft Graph PowerShell SDK

Required permissions:

- User.Read.All
- Device.Read.All
- Group.Read.All
- Group.ReadWrite.All
- GroupMember.Read.All
- GroupMember.ReadWrite.All

## Authentication Options

### Device Code Authentication

Recommended for:

- Windows Terminal
- VS Code
- Remote PowerShell sessions
- Environments where browser prompts may be hidden

### Interactive Browser Authentication

Recommended when Device Code Authentication is not permitted.

### App-Only Authentication

Recommended for:

- Automation
- Scheduled execution
- Service accounts

Requires:

- App Registration
- Certificate
- Appropriate Microsoft Graph Application Permissions

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
