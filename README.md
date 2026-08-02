# User-to-Device Group Sync for Microsoft Entra ID

Synchronize Microsoft Entra registered/owned devices with a device security group based on membership of a source user security group.

## Overview

This PowerShell script reads the user members of a source Microsoft Entra ID security group, resolves each user's registered and/or owned devices, and synchronizes those device objects into a target Microsoft Entra ID device security group. It is generic and not tied to any single scenario - useful for Endpoint DLP device scoping, device-targeted Conditional Access/Intune policy testing, or any other case where device group membership needs to be derived from user group membership.

## Key Features

- **Flexible group resolution** - source and target groups can be referenced by exact display name or by object ID.
- **Source vs. target group behavior differs on purpose**:
  - The **source user group** is treated as a business-owned object. The script never creates it automatically. If it can't be found or contains no users, the script pauses, explains what's needed, and lets you retry the name.
  - The **target device group** is optional to pre-create. If it doesn't exist, the script offers to create it automatically (as a static security group), waits for Microsoft Entra ID replication, and continues.
- **Transitive or direct source membership** - nested user groups are included by default.
- **Registered, Owned, or Both** device relationship modes.
- **Add and remove logic** - adds missing desired devices to the target group, and removes stale devices no longer associated with source users (configurable).
- **Multiple authentication methods** - Device Code, Interactive Browser, or App-only Certificate, with an automatic fallback menu if one method fails.
- **Automatic missing-module installation** - detects and installs any missing required Microsoft.Graph module in the same run, with a three-tier fallback strategy (standard install, dedicated non-Documents folder, then PSResourceGet) to work around known PackageManagement/OneDrive/Controlled Folder Access issues, with no need to close and reopen PowerShell in the normal case.
- **Self-healing module corruption detection** - automatically detects and repairs a module that Windows Defender Controlled Folder Access silently corrupted mid-install.
- **Retry logic with backoff** for transient/throttled Microsoft Graph errors.
- **-WhatIf / -Confirm support** via PowerShell ShouldProcess.
- **Automatic CSV reporting** to a timestamped file in the current working directory, including a separate report of users with no matching devices. Use `-ReportPath` to choose another path.
- **Accessibility-friendly console output** - explicit text labels (`[SUCCESS]`, `[WARNING]`, `[ERROR]`, `[ACTION REQUIRED]`) rather than relying on color alone.
- **Clean Microsoft Graph disconnect** on exit, whether the run succeeded or failed.

## Prerequisites

- PowerShell 5.1 or PowerShell 7+
- Microsoft Graph PowerShell SDK modules (installed automatically if missing):
  - `Microsoft.Graph.Authentication`
  - `Microsoft.Graph.Groups`
  - `Microsoft.Graph.Users`
  - `Microsoft.Graph.Identity.DirectoryManagement`

### Required Microsoft Graph permissions

**Delegated** (interactive sign-in):

- `Group.Read.All`
- `GroupMember.ReadWrite.All`
- `Group.ReadWrite.All` (only needed if the script creates the target device group)
- `User.Read.All`
- `Device.Read.All`
- `Directory.Read.All`

**Application** (app-only certificate authentication) - same permission set, granted as application permissions with admin consent.

## Usage

Run `.\Sync-UserGroupDevicesToDeviceGroup.ps1` as is with no switches to be prompted for the required source group and target group. By default, the script syncs registered devices from transitive group members, removes stale devices, excludes disabled devices, authenticates with Device Code and falls back to Interactive browser sign-in if needed, installs missing modules, retries Graph errors up to three times with a three-second base delay, and writes a timestamped CSV report to the current directory.

### Basic sync with -WhatIf (dry run)

```powershell
.\Sync-UserGroupDevicesToDeviceGroup.ps1 `
    -SourceUserGroup "All Field Users" `
    -TargetDeviceGroup "All Field User Devices" `
    -WhatIf
```

### Sync by object ID with both device relationship types and a CSV report

```powershell
.\Sync-UserGroupDevicesToDeviceGroup.ps1 `
    -SourceUserGroupId "00000000-0000-0000-0000-000000000000" `
    -TargetDeviceGroupId "11111111-1111-1111-1111-111111111111" `
    -DeviceRelationship Both `
    -ReportPath ".\sync-report.csv"
```

### Force Device Code authentication (recommended if interactive browser sign-in hangs)

```powershell
.\Sync-UserGroupDevicesToDeviceGroup.ps1 `
    -SourceUserGroup "All Field Users" `
    -TargetDeviceGroup "All Field User Devices" `
    -AuthenticationMethod DeviceCode
```

### Let the target device group be created automatically if missing

```powershell
.\Sync-UserGroupDevicesToDeviceGroup.ps1 `
    -SourceUserGroup "All Field Users"
```

(Omit `-TargetDeviceGroup`/`-TargetDeviceGroupId` and the script will prompt for a name and offer to create it.)

### Disable automatic module installation

```powershell
.\Sync-UserGroupDevicesToDeviceGroup.ps1 `
    -SourceUserGroup "All Field Users" `
    -TargetDeviceGroup "All Field User Devices" `
    -InstallMissingModules:$false
```

## Parameters

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `-SourceUserGroup` | string | (required, `ByDisplayName` set) | Source user group display name. Aliases: `-SourceGroup`, `-SourceGroupName`. |
| `-TargetDeviceGroup` | string | none | Target device group display name. Optional - if omitted or not found, the script offers to create it. Aliases: `-TargetGroup`, `-TargetGroupName`, `-DestinationDeviceGroup`. |
| `-SourceUserGroupId` | string (GUID) | (required, `ById` set) | Source user group object ID. |
| `-TargetDeviceGroupId` | string (GUID) | none | Target device group object ID. |
| `-DeviceRelationship` | `Registered` \| `Owned` \| `Both` | `Registered` | Which user-device relationship(s) to sync. |
| `-UseTransitiveMembers` | bool | `$true` | Include nested/transitive source group members. |
| `-RemoveStaleDevices` | bool | `$true` | Remove devices from the target group that no longer match a source user. |
| `-IncludeDisabledDevices` | switch | off | Include disabled (`accountEnabled = $false`) devices. |
| `-DeviceOperatingSystem` | string[] | none | Only include devices with an OS in this list. |
| `-ExcludeDeviceId` | string[] | none | Exclude specific devices by object ID or Entra device ID. Aliases: `-ExcludeDeviceObjectId`, `-ExcludeAzureAdDeviceId`. |
| `-TenantId` | string | none | Target a specific tenant during authentication. |
| `-AuthenticationMethod` | `Auto` \| `DeviceCode` \| `Interactive` \| `Certificate` | `Auto` | Authentication method. `Auto` tries Device Code, then Interactive. |
| `-ClientId` | string | none | App registration client ID (Certificate auth). |
| `-CertificateThumbprint` | string | none | Certificate thumbprint (Certificate auth). |
| `-SkipGraphConnect` | switch | off | Skip connecting; use an existing Graph session. The script will also skip disconnecting on exit in this case. |
| `-InstallMissingModules` | switch | **on by default** | Automatically install any missing required module. Use `-InstallMissingModules:$false` to disable and fail fast instead. |
| `-RetryCount` | int (1-10) | `3` | Max retry attempts for retryable Graph errors. |
| `-RetryDelaySeconds` | int (1-60) | `3` | Base delay between retries (multiplied by attempt number). |
| `-ReportPath` | string | `UserGroupDeviceSync-yyyyMMdd-HHmmss.csv` in the current working directory | Override the CSV output path. A second `-UsersWithoutDevices` CSV is written alongside it if applicable. |
| `-NoInteractiveRetry` | switch | off | Disable interactive pause/retry prompts; fail immediately instead (useful for unattended/scheduled runs). |

`-WhatIf` and `-Confirm` are also supported (via `SupportsShouldProcess`).

## Known Environment Issues This Script Works Around

- **Interactive browser sign-in hangs with no window appearing**: a known Microsoft Graph SDK/Windows WAM broker limitation when PowerShell is running elevated or in an embedded terminal. Use `-AuthenticationMethod DeviceCode` instead.
- **"Administrator rights are required" during module install despite `-Scope CurrentUser`**: can happen when the Documents-based module path is affected by OneDrive folder redirection. The script automatically falls back to a dedicated, non-Documents cache folder.
- **`ProviderFailToDownloadFile` during module install**: a known PackageManagement/NuGet-provider download defect. The script detects this specific error and automatically falls back to `Install-PSResource`/PSResourceGet, which uses an independent download implementation.
- **Windows Defender Controlled Folder Access silently corrupting a module install**: the script detects CFA status, explains the exact remediation (including the full executable path to allow-list), and automatically repairs a corrupted module install in its own dedicated cache folder without requiring a restart.

## License

See [LICENSE](LICENSE).
