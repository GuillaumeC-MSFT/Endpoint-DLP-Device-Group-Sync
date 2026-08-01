#requires -Version 5.1
<#
.SYNOPSIS
Synchronizes devices associated with members of a source user group into a target device group.

.DESCRIPTION
This script reads users from a source Entra ID group, resolves each user's registered and/or owned devices,
and then synchronizes those device objects into a target Entra ID security group.

By default, the script:
- Uses transitive source-user-group membership, so nested user groups are included.
- Uses registered devices only, which is the most common Intune assignment mapping pattern.
- Adds missing desired devices to the target device group.
- Removes stale devices from the target device group when they are no longer associated with source users.
- Supports -WhatIf and -Confirm through PowerShell ShouldProcess.

Examples:

  .\Sync-UserGroupDevicesToDeviceGroup.ps1 `
      -SourceUserGroup "All Field Users" `
      -TargetDeviceGroup "All Field User Devices" `
      -WhatIf

  .\Sync-UserGroupDevicesToDeviceGroup.ps1 `
      -SourceUserGroupId "00000000-0000-0000-0000-000000000000" `
      -TargetDeviceGroupId "11111111-1111-1111-1111-111111111111" `
      -DeviceRelationship Both `
      -ReportPath ".\sync-report.csv"

.NOTES
Required Microsoft Graph delegated permissions:
- Group.Read.All
- GroupMember.ReadWrite.All
- User.Read.All
- Device.Read.All
- Directory.Read.All

Required Microsoft Graph PowerShell modules:
- Microsoft.Graph.Authentication
- Microsoft.Graph.Groups
- Microsoft.Graph.Users
- Microsoft.Graph.Identity.DirectoryManagement
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium', DefaultParameterSetName = 'ByDisplayName')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'ByDisplayName')]
    [ValidateNotNullOrEmpty()]
    [Alias('SourceGroup', 'SourceGroupName')]
    [string]$SourceUserGroup,

    [Parameter(Mandatory = $true, ParameterSetName = 'ByDisplayName')]
    [ValidateNotNullOrEmpty()]
    [Alias('TargetGroup', 'TargetGroupName')]
    [string]$TargetDeviceGroup,

    [Parameter(Mandatory = $true, ParameterSetName = 'ById')]
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string]$SourceUserGroupId,

    [Parameter(Mandatory = $true, ParameterSetName = 'ById')]
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string]$TargetDeviceGroupId,

    [Parameter()]
    [ValidateSet('Registered', 'Owned', 'Both')]
    [string]$DeviceRelationship = 'Registered',

    [Parameter()]
    [bool]$UseTransitiveMembers = $true,

    [Parameter()]
    [bool]$RemoveStaleDevices = $true,

    [Parameter()]
    [switch]$IncludeDisabledDevices,

    [Parameter()]
    [string[]]$DeviceOperatingSystem,

    [Parameter()]
    [Alias('ExcludeDeviceObjectId', 'ExcludeAzureAdDeviceId')]
    [string[]]$ExcludeDeviceId,

    [Parameter()]
    [string]$TenantId,

    [Parameter()]
    [switch]$SkipGraphConnect,

    [Parameter()]
    [switch]$InstallMissingModules,

    [Parameter()]
    [ValidateRange(1, 10)]
    [int]$RetryCount = 3,

    [Parameter()]
    [ValidateRange(1, 60)]
    [int]$RetryDelaySeconds = 3,

    [Parameter()]
    [string]$ReportPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter()]
        [ValidateSet('Info', 'Warning', 'Error', 'Success', 'Debug')]
        [string]$Level = 'Info'
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $prefix = "[$timestamp] [$Level]"

    switch ($Level) {
        'Warning' { Write-Warning "$prefix $Message" }
        'Error'   { Write-Host "$prefix $Message" -ForegroundColor Red }
        'Success' { Write-Host "$prefix $Message" -ForegroundColor Green }
        'Debug'   { Write-Verbose "$prefix $Message" }
        default   { Write-Host "$prefix $Message" }
    }
}

function Test-IsGuid {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Value
    )

    $parsedGuid = [Guid]::Empty
    return [Guid]::TryParse($Value, [ref]$parsedGuid)
}

function ConvertTo-ODataStringLiteral {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    return $Value.Replace("'", "''")
}

function Get-GraphObjectValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [object]$Object,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if ($null -eq $Object) {
        return $null
    }

    $directProperty = $Object.PSObject.Properties[$Name]
    if ($null -ne $directProperty -and $null -ne $directProperty.Value) {
        return $directProperty.Value
    }

    $pascalName = if ($Name.Length -gt 1) { $Name.Substring(0, 1).ToUpperInvariant() + $Name.Substring(1) } else { $Name.ToUpperInvariant() }
    $pascalProperty = $Object.PSObject.Properties[$pascalName]
    if ($null -ne $pascalProperty -and $null -ne $pascalProperty.Value) {
        return $pascalProperty.Value
    }

    $additionalProperty = $Object.PSObject.Properties['AdditionalProperties']
    if ($null -ne $additionalProperty -and $additionalProperty.Value -is [System.Collections.IDictionary]) {
        $additional = $additionalProperty.Value
        if ($additional.Contains($Name)) {
            return $additional[$Name]
        }

        if ($additional.Contains($pascalName)) {
            return $additional[$pascalName]
        }
    }

    return $null
}

function Get-GraphObjectId {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Object
    )

    foreach ($name in @('Id', 'id')) {
        $value = Get-GraphObjectValue -Object $Object -Name $name
        if (-not [string]::IsNullOrWhiteSpace([string]$value)) {
            return [string]$value
        }
    }

    return $null
}

function Get-GraphObjectType {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Object
    )

    $odataType = Get-GraphObjectValue -Object $Object -Name '@odata.type'
    if (-not [string]::IsNullOrWhiteSpace([string]$odataType)) {
        return ([string]$odataType).TrimStart('#')
    }

    $typeName = $Object.GetType().FullName
    if ($typeName -match 'User') {
        return 'microsoft.graph.user'
    }

    if ($typeName -match 'Device') {
        return 'microsoft.graph.device'
    }

    if ($typeName -match 'Group') {
        return 'microsoft.graph.group'
    }

    return $typeName
}

function Test-GraphObjectType {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Object,

        [Parameter(Mandatory = $true)]
        [ValidateSet('User', 'Device', 'Group')]
        [string]$ExpectedType
    )

    $actualType = Get-GraphObjectType -Object $Object

    switch ($ExpectedType) {
        'User'   { return $actualType -match '(?i)(^|\.)user$' }
        'Device' { return $actualType -match '(?i)(^|\.)device$' }
        'Group'  { return $actualType -match '(?i)(^|\.)group$' }
    }
}

function Import-RequiredGraphModules {
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$InstallIfMissing
    )

    $requiredModules = @(
        'Microsoft.Graph.Authentication',
        'Microsoft.Graph.Groups',
        'Microsoft.Graph.Users',
        'Microsoft.Graph.Identity.DirectoryManagement'
    )

    foreach ($moduleName in $requiredModules) {
        $availableModule = Get-Module -ListAvailable -Name $moduleName | Sort-Object Version -Descending | Select-Object -First 1

        if ($null -eq $availableModule) {
            if ($InstallIfMissing) {
                Write-Log -Message "Installing missing module '$moduleName' in CurrentUser scope." -Level Info
                Install-Module -Name $moduleName -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
            }
            else {
                throw "Required module '$moduleName' is not installed. Re-run with -InstallMissingModules or install it manually with: Install-Module $moduleName -Scope CurrentUser"
            }
        }

        Import-Module -Name $moduleName -ErrorAction Stop
    }
}

function Connect-GraphIfNeeded {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$TenantIdValue,

        [Parameter()]
        [switch]$SkipConnect
    )

    if ($SkipConnect) {
        Write-Log -Message 'Skipping Connect-MgGraph because -SkipGraphConnect was specified.' -Level Info
        return
    }

    $requiredScopes = @(
        'Group.Read.All',
        'GroupMember.ReadWrite.All',
        'User.Read.All',
        'Device.Read.All',
        'Directory.Read.All'
    )

    $context = Get-MgContext
    $needsConnection = $true

    if ($null -ne $context -and $null -ne $context.Account) {
        $existingScopes = @($context.Scopes)
        $missingScopes = @($requiredScopes | Where-Object { $_ -notin $existingScopes })
        if ($missingScopes.Count -eq 0) {
            $needsConnection = $false
            Write-Log -Message "Using existing Microsoft Graph connection for account '$($context.Account)'." -Level Info
        }
        else {
            Write-Log -Message "Existing Microsoft Graph connection is missing scope(s): $($missingScopes -join ', '). Reconnecting." -Level Warning
        }
    }

    if ($needsConnection) {
        $connectParameters = @{ Scopes = $requiredScopes; NoWelcome = $true }
        if (-not [string]::IsNullOrWhiteSpace($TenantIdValue)) {
            $connectParameters['TenantId'] = $TenantIdValue
        }

        Connect-MgGraph @connectParameters -ErrorAction Stop | Out-Null
        $newContext = Get-MgContext
        Write-Log -Message "Connected to Microsoft Graph as '$($newContext.Account)'." -Level Success
    }
}

function Invoke-WithRetry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock,

        [Parameter(Mandatory = $true)]
        [string]$OperationName,

        [Parameter()]
        [int]$MaximumAttempts = 3,

        [Parameter()]
        [int]$DelaySeconds = 3
    )

    $attempt = 0

    while ($true) {
        $attempt++

        try {
            return & $ScriptBlock
        }
        catch {
            $message = $_.Exception.Message
            $isRetryable = $message -match '(?i)(429|throttl|timeout|temporar|503|504|gateway|too many requests|service unavailable)'

            if (-not $isRetryable -or $attempt -ge $MaximumAttempts) {
                throw
            }

            $sleepSeconds = [Math]::Max(1, $DelaySeconds * $attempt)
            Write-Log -Message "$OperationName failed on attempt $attempt of $MaximumAttempts. Retrying in $sleepSeconds second(s). Error: $message" -Level Warning
            Start-Sleep -Seconds $sleepSeconds
        }
    }
}

function Resolve-EntraGroup {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$GroupReference,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Source user group', 'Target device group')]
        [string]$Role
    )

    $groupProperties = @('id', 'displayName', 'groupTypes', 'membershipRule', 'securityEnabled', 'mailEnabled')

    if (Test-IsGuid -Value $GroupReference) {
        Write-Log -Message "Resolving $Role by object ID '$GroupReference'." -Level Info
        return Get-MgGroup -GroupId $GroupReference -Property $groupProperties -ErrorAction Stop
    }

    Write-Log -Message "Resolving $Role by exact display name '$GroupReference'." -Level Info
    $escapedName = ConvertTo-ODataStringLiteral -Value $GroupReference
    $matches = @(Get-MgGroup -Filter "displayName eq '$escapedName'" -ConsistencyLevel eventual -All -Property $groupProperties -ErrorAction Stop)

    if ($matches.Count -eq 0) {
        throw "$Role '$GroupReference' was not found by exact display name. Use the object ID if the display name is not exact."
    }

    if ($matches.Count -gt 1) {
        $duplicateSummary = $matches | ForEach-Object { "DisplayName='$($_.DisplayName)', Id='$($_.Id)'" }
        throw "$Role '$GroupReference' matched multiple groups. Re-run with the object ID. Matches: $($duplicateSummary -join '; ')"
    }

    return $matches[0]
}

function Test-StaticSecurityGroup {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Group,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Source user group', 'Target device group')]
        [string]$Role
    )

    $groupTypes = @($Group.GroupTypes)
    $isDynamic = $groupTypes -contains 'DynamicMembership' -or -not [string]::IsNullOrWhiteSpace([string]$Group.MembershipRule)

    if ($Role -eq 'Target device group' -and $isDynamic) {
        throw "The target device group '$($Group.DisplayName)' is dynamic. Static membership changes cannot be applied to dynamic groups."
    }

    if ($Role -eq 'Target device group' -and $Group.SecurityEnabled -ne $true) {
        Write-Log -Message "Target group '$($Group.DisplayName)' is not marked securityEnabled. Intune device assignments typically require a security-enabled group." -Level Warning
    }
}

function Get-UserMembersFromGroup {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$GroupId,

        [Parameter(Mandatory = $true)]
        [bool]$Transitive
    )

    $memberProperties = @('id', 'displayName', 'userPrincipalName', 'mail')

    if ($Transitive) {
        Write-Log -Message 'Retrieving transitive source group members.' -Level Info
        $rawMembers = @(Get-MgGroupTransitiveMember -GroupId $GroupId -All -ConsistencyLevel eventual -Property $memberProperties -ErrorAction Stop)
    }
    else {
        Write-Log -Message 'Retrieving direct source group members.' -Level Info
        $rawMembers = @(Get-MgGroupMember -GroupId $GroupId -All -Property $memberProperties -ErrorAction Stop)
    }

    $usersById = [ordered]@{}
    $skippedMembers = 0

    foreach ($member in $rawMembers) {
        if (-not (Test-GraphObjectType -Object $member -ExpectedType User)) {
            $skippedMembers++
            continue
        }

        $memberId = Get-GraphObjectId -Object $member
        if ([string]::IsNullOrWhiteSpace($memberId)) {
            $skippedMembers++
            continue
        }

        if (-not $usersById.Contains($memberId)) {
            $displayName = Get-GraphObjectValue -Object $member -Name 'displayName'
            $userPrincipalName = Get-GraphObjectValue -Object $member -Name 'userPrincipalName'
            $mail = Get-GraphObjectValue -Object $member -Name 'mail'

            $usersById[$memberId] = [pscustomobject]@{
                Id                = $memberId
                DisplayName       = [string]$displayName
                UserPrincipalName = [string]$userPrincipalName
                Mail              = [string]$mail
            }
        }
    }

    Write-Log -Message "Resolved $($usersById.Count) user member(s). Skipped $skippedMembers non-user or malformed member object(s)." -Level Info
    return @($usersById.Values)
}

function Get-UserDeviceObjects {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$User,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Registered', 'Owned', 'Both')]
        [string]$RelationshipMode
    )

    $deviceProperties = @(
        'id',
        'displayName',
        'deviceId',
        'operatingSystem',
        'accountEnabled',
        'trustType',
        'approximateLastSignInDateTime'
    )

    $results = New-Object System.Collections.Generic.List[object]

    if ($RelationshipMode -in @('Registered', 'Both')) {
        $registeredDevices = @(Invoke-WithRetry -OperationName "Get registered devices for user '$($User.Id)'" -MaximumAttempts $RetryCount -DelaySeconds $RetryDelaySeconds -ScriptBlock {
            Get-MgUserRegisteredDevice -UserId $User.Id -All -Property $deviceProperties -ErrorAction Stop
        })

        foreach ($device in $registeredDevices) {
            $results.Add([pscustomobject]@{ Relationship = 'Registered'; Device = $device })
        }
    }

    if ($RelationshipMode -in @('Owned', 'Both')) {
        $ownedDevices = @(Invoke-WithRetry -OperationName "Get owned devices for user '$($User.Id)'" -MaximumAttempts $RetryCount -DelaySeconds $RetryDelaySeconds -ScriptBlock {
            Get-MgUserOwnedDevice -UserId $User.Id -All -Property $deviceProperties -ErrorAction Stop
        })

        foreach ($device in $ownedDevices) {
            $results.Add([pscustomobject]@{ Relationship = 'Owned'; Device = $device })
        }
    }

    return @($results)
}

function New-DeviceRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Device
    )

    $objectId = Get-GraphObjectId -Object $Device
    $displayName = Get-GraphObjectValue -Object $Device -Name 'displayName'
    $azureAdDeviceId = Get-GraphObjectValue -Object $Device -Name 'deviceId'
    $operatingSystem = Get-GraphObjectValue -Object $Device -Name 'operatingSystem'
    $accountEnabled = Get-GraphObjectValue -Object $Device -Name 'accountEnabled'
    $trustType = Get-GraphObjectValue -Object $Device -Name 'trustType'
    $approximateLastSignIn = Get-GraphObjectValue -Object $Device -Name 'approximateLastSignInDateTime'

    return [pscustomobject]@{
        Id                            = [string]$objectId
        DisplayName                   = [string]$displayName
        DeviceId                      = [string]$azureAdDeviceId
        OperatingSystem               = [string]$operatingSystem
        AccountEnabled                = $accountEnabled
        TrustType                     = [string]$trustType
        ApproximateLastSignInDateTime = $approximateLastSignIn
        SourceUsers                   = [ordered]@{}
        Relationships                 = [ordered]@{}
    }
}

function Add-DesiredDeviceRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.Specialized.OrderedDictionary]$DesiredDevices,

        [Parameter(Mandatory = $true)]
        [object]$Device,

        [Parameter(Mandatory = $true)]
        [string]$Relationship,

        [Parameter(Mandatory = $true)]
        [pscustomobject]$User
    )

    if (-not (Test-GraphObjectType -Object $Device -ExpectedType Device)) {
        return $false
    }

    $objectId = Get-GraphObjectId -Object $Device
    if ([string]::IsNullOrWhiteSpace($objectId)) {
        return $false
    }

    $azureAdDeviceId = [string](Get-GraphObjectValue -Object $Device -Name 'deviceId')
    if (Test-IsExcludedDevice -ObjectId $objectId -AzureAdDeviceId $azureAdDeviceId) {
        Write-Log -Message "Skipping excluded device '$objectId'." -Level Info
        return $false
    }

    $operatingSystem = [string](Get-GraphObjectValue -Object $Device -Name 'operatingSystem')
    if ($script:DeviceOperatingSystemFilter.Count -gt 0 -and $operatingSystem -notin $script:DeviceOperatingSystemFilter) {
        return $false
    }

    $accountEnabled = Get-GraphObjectValue -Object $Device -Name 'accountEnabled'
    if (-not $IncludeDisabledDevices -and $null -ne $accountEnabled -and $accountEnabled -eq $false) {
        return $false
    }

    if (-not $DesiredDevices.Contains($objectId)) {
        $DesiredDevices[$objectId] = New-DeviceRecord -Device $Device
    }

    $record = $DesiredDevices[$objectId]
    $userLabel = if (-not [string]::IsNullOrWhiteSpace($User.UserPrincipalName)) { $User.UserPrincipalName } elseif (-not [string]::IsNullOrWhiteSpace($User.DisplayName)) { $User.DisplayName } else { $User.Id }
    $record.SourceUsers[$userLabel] = $true
    $record.Relationships[$Relationship] = $true

    return $true
}

function Test-IsExcludedDevice {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$ObjectId,

        [Parameter()]
        [string]$AzureAdDeviceId
    )

    foreach ($candidate in @($ObjectId, $AzureAdDeviceId)) {
        if ([string]::IsNullOrWhiteSpace($candidate)) {
            continue
        }

        if ($script:ExcludedDeviceLookup.Contains($candidate.ToLowerInvariant())) {
            return $true
        }
    }

    return $false
}

function Get-TargetGroupDeviceMembers {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$GroupId
    )

    $memberProperties = @(
        'id',
        'displayName',
        'deviceId',
        'operatingSystem',
        'accountEnabled',
        'trustType',
        'approximateLastSignInDateTime'
    )

    Write-Log -Message 'Retrieving current target group members.' -Level Info
    $rawMembers = @(Get-MgGroupMember -GroupId $GroupId -All -Property $memberProperties -ErrorAction Stop)
    $devices = [ordered]@{}
    $skippedMembers = 0

    foreach ($member in $rawMembers) {
        if (-not (Test-GraphObjectType -Object $member -ExpectedType Device)) {
            $skippedMembers++
            continue
        }

        $objectId = Get-GraphObjectId -Object $member
        if ([string]::IsNullOrWhiteSpace($objectId)) {
            $skippedMembers++
            continue
        }

        if (-not $devices.Contains($objectId)) {
            $devices[$objectId] = New-DeviceRecord -Device $member
        }
    }

    Write-Log -Message "Resolved $($devices.Count) current device member(s) in target group. Ignored $skippedMembers non-device or malformed member object(s)." -Level Info
    return $devices
}

function Join-OrderedDictionaryKeys {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.Specialized.OrderedDictionary]$Dictionary
    )

    if ($Dictionary.Count -eq 0) {
        return ''
    }

    return [string]::Join('; ', [string[]]$Dictionary.Keys)
}

function New-ReportRow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Action,

        [Parameter(Mandatory = $true)]
        [pscustomobject]$DeviceRecord,

        [Parameter()]
        [string]$Result = ''
    )

    return [pscustomobject]@{
        Action                        = $Action
        Result                        = $Result
        DeviceObjectId                = $DeviceRecord.Id
        DeviceId                      = $DeviceRecord.DeviceId
        DisplayName                   = $DeviceRecord.DisplayName
        OperatingSystem               = $DeviceRecord.OperatingSystem
        AccountEnabled                = $DeviceRecord.AccountEnabled
        TrustType                     = $DeviceRecord.TrustType
        ApproximateLastSignInDateTime = $DeviceRecord.ApproximateLastSignInDateTime
        SourceUsers                   = Join-OrderedDictionaryKeys -Dictionary $DeviceRecord.SourceUsers
        Relationships                 = Join-OrderedDictionaryKeys -Dictionary $DeviceRecord.Relationships
    }
}

function Add-DeviceToGroup {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$GroupId,

        [Parameter(Mandatory = $true)]
        [pscustomobject]$DeviceRecord
    )

    $bodyParameter = @{
        '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$($DeviceRecord.Id)"
    }

    Invoke-WithRetry -OperationName "Add device '$($DeviceRecord.Id)' to target group" -MaximumAttempts $RetryCount -DelaySeconds $RetryDelaySeconds -ScriptBlock {
        New-MgGroupMemberByRef -GroupId $GroupId -BodyParameter $bodyParameter -ErrorAction Stop
    } | Out-Null
}

function Remove-DeviceFromGroup {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$GroupId,

        [Parameter(Mandatory = $true)]
        [pscustomobject]$DeviceRecord
    )

    Invoke-WithRetry -OperationName "Remove device '$($DeviceRecord.Id)' from target group" -MaximumAttempts $RetryCount -DelaySeconds $RetryDelaySeconds -ScriptBlock {
        Remove-MgGroupMemberByRef -GroupId $GroupId -DirectoryObjectId $DeviceRecord.Id -ErrorAction Stop
    } | Out-Null
}

$script:DeviceOperatingSystemFilter = @()
if ($null -ne $DeviceOperatingSystem -and $DeviceOperatingSystem.Count -gt 0) {
    $script:DeviceOperatingSystemFilter = @($DeviceOperatingSystem | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
}

$script:ExcludedDeviceLookup = @{}
if ($null -ne $ExcludeDeviceId -and $ExcludeDeviceId.Count -gt 0) {
    foreach ($excludedDevice in $ExcludeDeviceId) {
        if (-not [string]::IsNullOrWhiteSpace($excludedDevice)) {
            $script:ExcludedDeviceLookup[$excludedDevice.ToLowerInvariant()] = $true
        }
    }
}

try {
    Import-RequiredGraphModules -InstallIfMissing:$InstallMissingModules
    Connect-GraphIfNeeded -TenantIdValue $TenantId -SkipConnect:$SkipGraphConnect

    if ($PSCmdlet.ParameterSetName -eq 'ById') {
        $sourceGroupReference = $SourceUserGroupId
        $targetGroupReference = $TargetDeviceGroupId
    }
    else {
        $sourceGroupReference = $SourceUserGroup
        $targetGroupReference = $TargetDeviceGroup
    }

    $sourceGroup = Resolve-EntraGroup -GroupReference $sourceGroupReference -Role 'Source user group'
    $targetGroup = Resolve-EntraGroup -GroupReference $targetGroupReference -Role 'Target device group'

    Test-StaticSecurityGroup -Group $sourceGroup -Role 'Source user group'
    Test-StaticSecurityGroup -Group $targetGroup -Role 'Target device group'

    Write-Log -Message "Source user group: '$($sourceGroup.DisplayName)' [$($sourceGroup.Id)]" -Level Success
    Write-Log -Message "Target device group: '$($targetGroup.DisplayName)' [$($targetGroup.Id)]" -Level Success
    Write-Log -Message "Device relationship mode: $DeviceRelationship" -Level Info
    Write-Log -Message "Use transitive members: $UseTransitiveMembers" -Level Info
    Write-Log -Message "Remove stale devices: $RemoveStaleDevices" -Level Info

    $sourceUsers = @(Get-UserMembersFromGroup -GroupId $sourceGroup.Id -Transitive $UseTransitiveMembers)
    $desiredDevices = [ordered]@{}
    $processedUsers = 0
    $rawDeviceRelationshipCount = 0
    $acceptedDeviceRelationshipCount = 0

    foreach ($user in $sourceUsers) {
        $processedUsers++
        $userLabel = if (-not [string]::IsNullOrWhiteSpace($user.UserPrincipalName)) { $user.UserPrincipalName } elseif (-not [string]::IsNullOrWhiteSpace($user.DisplayName)) { $user.DisplayName } else { $user.Id }
        Write-Progress -Activity 'Resolving user devices' -Status $userLabel -PercentComplete (($processedUsers / [Math]::Max(1, $sourceUsers.Count)) * 100)

        $userDeviceObjects = @(Get-UserDeviceObjects -User $user -RelationshipMode $DeviceRelationship)
        $rawDeviceRelationshipCount += $userDeviceObjects.Count

        foreach ($userDeviceObject in $userDeviceObjects) {
            $added = Add-DesiredDeviceRecord -DesiredDevices $desiredDevices -Device $userDeviceObject.Device -Relationship $userDeviceObject.Relationship -User $user
            if ($added) {
                $acceptedDeviceRelationshipCount++
            }
        }
    }

    Write-Progress -Activity 'Resolving user devices' -Completed

    $currentDevices = Get-TargetGroupDeviceMembers -GroupId $targetGroup.Id

    $deviceIdsToAdd = @($desiredDevices.Keys | Where-Object { -not $currentDevices.Contains($_) })
    $deviceIdsToRemove = @()

    if ($RemoveStaleDevices) {
        $deviceIdsToRemove = @($currentDevices.Keys | Where-Object { -not $desiredDevices.Contains($_) })
    }

    $reportRows = New-Object System.Collections.Generic.List[object]

    Write-Log -Message "Source users processed: $($sourceUsers.Count)" -Level Info
    Write-Log -Message "Raw user-device relationship(s) found: $rawDeviceRelationshipCount" -Level Info
    Write-Log -Message "Accepted user-device relationship(s) after filters: $acceptedDeviceRelationshipCount" -Level Info
    Write-Log -Message "Unique desired device(s): $($desiredDevices.Count)" -Level Info
    Write-Log -Message "Current target device member(s): $($currentDevices.Count)" -Level Info
    Write-Log -Message "Device(s) to add: $($deviceIdsToAdd.Count)" -Level Info
    Write-Log -Message "Device(s) to remove: $($deviceIdsToRemove.Count)" -Level Info

    foreach ($deviceId in $deviceIdsToAdd) {
        $deviceRecord = $desiredDevices[$deviceId]
        $targetDescription = "target group '$($targetGroup.DisplayName)'"
        $actionDescription = "add device '$($deviceRecord.DisplayName)' [$($deviceRecord.Id)]"

        if ($PSCmdlet.ShouldProcess($targetDescription, $actionDescription)) {
            try {
                Add-DeviceToGroup -GroupId $targetGroup.Id -DeviceRecord $deviceRecord
                Write-Log -Message "Added device '$($deviceRecord.DisplayName)' [$($deviceRecord.Id)]." -Level Success
                $reportRows.Add((New-ReportRow -Action 'Add' -DeviceRecord $deviceRecord -Result 'Success'))
            }
            catch {
                $errorMessage = $_.Exception.Message
                if ($errorMessage -match '(?i)(already exist|added object references already exist|one or more added object references already exist)') {
                    Write-Log -Message "Device '$($deviceRecord.DisplayName)' [$($deviceRecord.Id)] was already a member. Treating as success." -Level Warning
                    $reportRows.Add((New-ReportRow -Action 'Add' -DeviceRecord $deviceRecord -Result 'AlreadyMember'))
                }
                else {
                    Write-Log -Message "Failed to add device '$($deviceRecord.DisplayName)' [$($deviceRecord.Id)]: $errorMessage" -Level Error
                    $reportRows.Add((New-ReportRow -Action 'Add' -DeviceRecord $deviceRecord -Result "Failed: $errorMessage"))
                }
            }
        }
        else {
            $reportRows.Add((New-ReportRow -Action 'Add' -DeviceRecord $deviceRecord -Result 'WhatIf'))
        }
    }

    foreach ($deviceId in $deviceIdsToRemove) {
        $deviceRecord = $currentDevices[$deviceId]
        $targetDescription = "target group '$($targetGroup.DisplayName)'"
        $actionDescription = "remove stale device '$($deviceRecord.DisplayName)' [$($deviceRecord.Id)]"

        if ($PSCmdlet.ShouldProcess($targetDescription, $actionDescription)) {
            try {
                Remove-DeviceFromGroup -GroupId $targetGroup.Id -DeviceRecord $deviceRecord
                Write-Log -Message "Removed stale device '$($deviceRecord.DisplayName)' [$($deviceRecord.Id)]." -Level Success
                $reportRows.Add((New-ReportRow -Action 'Remove' -DeviceRecord $deviceRecord -Result 'Success'))
            }
            catch {
                $errorMessage = $_.Exception.Message
                if ($errorMessage -match '(?i)(does not exist|not found|resource .* does not exist)') {
                    Write-Log -Message "Device '$($deviceRecord.DisplayName)' [$($deviceRecord.Id)] was already absent. Treating as success." -Level Warning
                    $reportRows.Add((New-ReportRow -Action 'Remove' -DeviceRecord $deviceRecord -Result 'AlreadyAbsent'))
                }
                else {
                    Write-Log -Message "Failed to remove device '$($deviceRecord.DisplayName)' [$($deviceRecord.Id)]: $errorMessage" -Level Error
                    $reportRows.Add((New-ReportRow -Action 'Remove' -DeviceRecord $deviceRecord -Result "Failed: $errorMessage"))
                }
            }
        }
        else {
            $reportRows.Add((New-ReportRow -Action 'Remove' -DeviceRecord $deviceRecord -Result 'WhatIf'))
        }
    }

    $unchangedDeviceIds = @($desiredDevices.Keys | Where-Object { $currentDevices.Contains($_) })
    foreach ($deviceId in $unchangedDeviceIds) {
        $reportRows.Add((New-ReportRow -Action 'Keep' -DeviceRecord $desiredDevices[$deviceId] -Result 'AlreadyMember'))
    }

    if (-not $RemoveStaleDevices) {
        $staleButKeptDeviceIds = @($currentDevices.Keys | Where-Object { -not $desiredDevices.Contains($_) })
        foreach ($deviceId in $staleButKeptDeviceIds) {
            $reportRows.Add((New-ReportRow -Action 'KeepStale' -DeviceRecord $currentDevices[$deviceId] -Result 'RemoveStaleDevicesFalse'))
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($ReportPath)) {
        $reportDirectory = Split-Path -Path $ReportPath -Parent
        if (-not [string]::IsNullOrWhiteSpace($reportDirectory) -and -not (Test-Path -Path $reportDirectory)) {
            New-Item -ItemType Directory -Path $reportDirectory -Force | Out-Null
        }

        $reportRows | Sort-Object Action, DisplayName, DeviceObjectId | Export-Csv -Path $ReportPath -NoTypeInformation -Encoding UTF8
        Write-Log -Message "Report written to '$ReportPath'." -Level Success
    }

    Write-Log -Message 'Synchronization completed.' -Level Success
    Write-Log -Message "Summary: users=$($sourceUsers.Count); desiredDevices=$($desiredDevices.Count); currentDevices=$($currentDevices.Count); add=$($deviceIdsToAdd.Count); remove=$($deviceIdsToRemove.Count); reportRows=$($reportRows.Count)." -Level Success
}
catch {
    Write-Log -Message $_.Exception.Message -Level Error
    throw
}
