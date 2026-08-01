#requires -Version 5.1
<#
.SYNOPSIS
Synchronizes Microsoft Entra ID devices associated with members of a source user group into a target device group.

.DESCRIPTION
This script reads users from a source Microsoft Entra ID security group, resolves each user's registered and/or owned devices,
and synchronizes those device objects into a target Microsoft Entra ID security group.

The utility is generic. It can support any scenario where device group membership needs to be derived from user group membership.
Endpoint DLP device scoping is one possible use case, but the script is not limited to Endpoint DLP.

Key behaviors:
- The source user group is a business-owned object and must already exist and contain at least one user. The script
  never creates the source user group; it will pause and let you retry the name if it cannot be found or is empty.
- The target device group may already exist, or the script can create it for you. If it cannot be found, you will be
  offered the option to create it automatically (as a static security group), after which the script waits for
  Microsoft Entra ID replication and continues automatically.
- Uses transitive source group membership by default, so nested user groups are included.
- Uses registered devices by default, with options for owned devices or both.
- Adds missing desired devices to the target device group.
- Removes stale devices by default when they are no longer associated with source users.
- Supports -WhatIf and -Confirm through PowerShell ShouldProcess.
- Includes authentication choices for device code, interactive browser, and app-only certificate authentication.
- Validates the Microsoft Graph context before Graph operations to avoid hidden re-authentication surprises.
- Uses accessibility-friendly text status labels instead of relying only on console colors.
- Disconnects the Microsoft Graph session automatically when the script finishes, whether it completed
  successfully or failed, unless -SkipGraphConnect was used (in which case the connection was supplied by
  the caller and is left untouched).

.EXAMPLE
.\Sync-UserGroupDevicesToDeviceGroup.ps1 `
    -SourceUserGroup "All Field Users" `
    -TargetDeviceGroup "All Field User Devices" `
    -WhatIf

.EXAMPLE
.\Sync-UserGroupDevicesToDeviceGroup.ps1 `
    -SourceUserGroupId "00000000-0000-0000-0000-000000000000" `
    -TargetDeviceGroupId "11111111-1111-1111-1111-111111111111" `
    -DeviceRelationship Both `
    -ReportPath ".\sync-report.csv"

.EXAMPLE
.\Sync-UserGroupDevicesToDeviceGroup.ps1 `
    -SourceUserGroup "All Field Users" `
    -TargetDeviceGroup "All Field User Devices" `
    -AuthenticationMethod DeviceCode `
    -InstallMissingModules

.NOTES
Script version: 3.3.0

Required Microsoft Graph delegated permissions:
- Group.Read.All
- GroupMember.ReadWrite.All
- Group.ReadWrite.All (only required if the script creates the target device group)
- User.Read.All
- Device.Read.All
- Directory.Read.All

Required Microsoft Graph application permissions for certificate/app-only authentication:
- Group.Read.All
- GroupMember.ReadWrite.All
- Group.ReadWrite.All (only required if the script creates the target device group)
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

    [Parameter(ParameterSetName = 'ByDisplayName')]
    [Alias('TargetGroup', 'TargetGroupName', 'DestinationDeviceGroup')]
    [string]$TargetDeviceGroup,

    [Parameter(Mandatory = $true, ParameterSetName = 'ById')]
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string]$SourceUserGroupId,

    [Parameter(ParameterSetName = 'ById')]
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
    [ValidateSet('Auto', 'DeviceCode', 'Interactive', 'Certificate')]
    [string]$AuthenticationMethod = 'Auto',

    [Parameter()]
    [string]$ClientId,

    [Parameter()]
    [string]$CertificateThumbprint,

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
    [string]$ReportPath,

    [Parameter()]
    [switch]$NoInteractiveRetry
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ScriptVersion = '3.7.0'
$script:ScriptName = 'Sync-UserGroupDevicesToDeviceGroup.ps1'

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter()]
        [ValidateSet('Info', 'Warning', 'Error', 'Success', 'Debug', 'Action')]
        [string]$Level = 'Info'
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $label = switch ($Level) {
        'Warning' { 'WARNING' }
        'Error'   { 'ERROR' }
        'Success' { 'SUCCESS' }
        'Debug'   { 'DEBUG' }
        'Action'  { 'ACTION REQUIRED' }
        default   { 'INFO' }
    }

    $line = "[$timestamp] [$label] $Message"

    switch ($Level) {
        'Warning' { Write-Warning $line }
        'Error'   { Write-Host $line -ForegroundColor Magenta }
        'Success' { Write-Host $line -ForegroundColor White }
        'Debug'   { Write-Verbose $line }
        'Action'  { Write-Host $line -ForegroundColor Cyan }
        default   { Write-Host $line }
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
    if ($null -ne $additionalProperty -and $null -ne $additionalProperty.Value) {
        $additional = $additionalProperty.Value

        # Note: Dictionary<TKey,TValue> (what Microsoft Graph SDK uses for AdditionalProperties)
        # exposes two ambiguous "Contains" members via explicit interface implementations
        # (ICollection<KeyValuePair>.Contains and IDictionary.Contains), which PowerShell's method
        # binder cannot resolve for a single string argument. ContainsKey() is unambiguous and public
        # on Dictionary, Hashtable, and OrderedDictionary alike, so it is used here instead.
        if ($additional.ContainsKey($Name)) {
            return $additional[$Name]
        }
        if ($additional.ContainsKey($pascalName)) {
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
    if ($typeName -match 'User') { return 'microsoft.graph.user' }
    if ($typeName -match 'Device') { return 'microsoft.graph.device' }
    if ($typeName -match 'Group') { return 'microsoft.graph.group' }

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
                $availableModule = Get-Module -ListAvailable -Name $moduleName | Sort-Object Version -Descending | Select-Object -First 1
            }
            else {
                throw "Required module '$moduleName' is not installed. Re-run with -InstallMissingModules or install it manually with: Install-Module $moduleName -Scope CurrentUser"
            }
        }

        Import-Module -Name $moduleName -ErrorAction Stop
        Write-Log -Message "Loaded module '$moduleName' version '$($availableModule.Version)'." -Level Debug
    }
}

function Get-DeviceCodeParameterName {
    [CmdletBinding()]
    param()

    $command = Get-Command -Name Connect-MgGraph -ErrorAction Stop
    if ($command.Parameters.ContainsKey('UseDeviceCode')) {
        return 'UseDeviceCode'
    }
    if ($command.Parameters.ContainsKey('UseDeviceAuthentication')) {
        return 'UseDeviceAuthentication'
    }

    return $null
}

function Get-SafeProperty {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [object]$InputObject,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    # Uses .PSObject.Properties[] rather than direct dot-notation so that a property which does not
    # exist on this installed SDK version (for example, 'AppName' on older Microsoft.Graph.Authentication
    # releases) returns $null instead of throwing a PropertyNotFoundException.
    if ($null -eq $InputObject) {
        return $null
    }

    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }

    return $property.Value
}

function Assert-GraphConnection {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$OperationName = 'Microsoft Graph operation'
    )

    $context = Get-MgContext
    if ($null -eq $context) {
        throw "Microsoft Graph authentication context is not available before: $OperationName. Re-run the script and authenticate again."
    }

    $accountText = [string](Get-SafeProperty -InputObject $context -Name 'Account')
    $appNameText = [string](Get-SafeProperty -InputObject $context -Name 'AppName')
    if ([string]::IsNullOrWhiteSpace($accountText) -and [string]::IsNullOrWhiteSpace($appNameText)) {
        throw "Microsoft Graph authentication context is incomplete before: $OperationName. Re-run the script and authenticate again."
    }

    return $true
}

function Connect-GraphOnce {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$RequiredScopes,

        [Parameter()]
        [string]$TenantIdValue,

        [Parameter(Mandatory = $true)]
        [ValidateSet('DeviceCode', 'Interactive', 'Certificate')]
        [string]$Method,

        [Parameter()]
        [string]$ClientIdValue,

        [Parameter()]
        [string]$CertificateThumbprintValue
    )

    $connectParameters = @{ NoWelcome = $true }

    $connectCommand = Get-Command -Name Connect-MgGraph -ErrorAction Stop
    if ($connectCommand.Parameters.ContainsKey('ContextScope')) {
        $connectParameters['ContextScope'] = 'Process'
    }

    if (-not [string]::IsNullOrWhiteSpace($TenantIdValue)) {
        $connectParameters['TenantId'] = $TenantIdValue
    }

    $isDeviceCodeFlow = $false

    switch ($Method) {
        'DeviceCode' {
            $isDeviceCodeFlow = $true
            $connectParameters['Scopes'] = $RequiredScopes
            $deviceCodeParameterName = Get-DeviceCodeParameterName
            if ([string]::IsNullOrWhiteSpace($deviceCodeParameterName)) {
                throw 'This installed version of Microsoft.Graph.Authentication does not expose a device-code authentication parameter. Use -AuthenticationMethod Interactive or update Microsoft.Graph.Authentication.'
            }
            $connectParameters[$deviceCodeParameterName] = $true
            Write-Log -Message 'Starting Microsoft Graph device-code authentication.' -Level Info
        }
        'Interactive' {
            $connectParameters['Scopes'] = $RequiredScopes
            Write-Log -Message 'Starting Microsoft Graph interactive browser authentication.' -Level Info
        }
        'Certificate' {
            if ([string]::IsNullOrWhiteSpace($TenantIdValue)) {
                throw 'TenantId is required for certificate authentication.'
            }
            if ([string]::IsNullOrWhiteSpace($ClientIdValue)) {
                throw 'ClientId is required for certificate authentication.'
            }
            if ([string]::IsNullOrWhiteSpace($CertificateThumbprintValue)) {
                throw 'CertificateThumbprint is required for certificate authentication.'
            }
            $connectParameters['ClientId'] = $ClientIdValue
            $connectParameters['CertificateThumbprint'] = $CertificateThumbprintValue
            Write-Log -Message 'Starting Microsoft Graph app-only certificate authentication.' -Level Info
        }
    }

    if ($isDeviceCodeFlow) {
        # KNOWN SDK BEHAVIOR (microsoftgraph/msgraph-sdk-powershell GitHub issue #2798, open as of this
        # writing): Connect-MgGraph -UseDeviceCode writes its "To sign in, use a web browser to open the
        # page https://microsoft.com/devicelogin and enter the code XXXXXXXX to authenticate" instructions
        # to the normal SUCCESS/output pipeline rather than directly to the host. Piping that output to
        # Out-Null (as every other authentication path in this script safely does, since they have nothing
        # useful to show) silently swallows those instructions. The script then appears to hang forever,
        # because it is in fact waiting on a code entry step the operator was never shown. Out-Host forces
        # the message to display immediately, without capturing/suppressing it, fixing this specific flow.
        Write-Log -Message 'Waiting for you to complete device-code sign-in. Watch for the code and URL below.' -Level Action
        Connect-MgGraph @connectParameters -ErrorAction Stop | Out-Host
    }
    else {
        Connect-MgGraph @connectParameters -ErrorAction Stop | Out-Null
    }

    $null = Assert-GraphConnection -OperationName 'post-authentication validation'

    $context = Get-MgContext
    $contextAccount = [string](Get-SafeProperty -InputObject $context -Name 'Account')
    $contextAppName = [string](Get-SafeProperty -InputObject $context -Name 'AppName')
    $identity = if (-not [string]::IsNullOrWhiteSpace($contextAccount)) { $contextAccount } elseif (-not [string]::IsNullOrWhiteSpace($contextAppName)) { $contextAppName } else { 'unknown identity' }
    Write-Log -Message "Connected to Microsoft Graph using $Method as '$identity'. TenantId='$($context.TenantId)'." -Level Success
}

function Connect-GraphIfNeeded {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$TenantIdValue,

        [Parameter()]
        [string]$ClientIdValue,

        [Parameter()]
        [string]$CertificateThumbprintValue,

        [Parameter()]
        [switch]$SkipConnect
    )

    if ($SkipConnect) {
        Write-Log -Message 'Skipping Connect-MgGraph because -SkipGraphConnect was specified.' -Level Info
        $null = Assert-GraphConnection -OperationName 'startup validation with -SkipGraphConnect'
        return
    }

    $requiredScopes = @(
        'Group.Read.All',
        'GroupMember.ReadWrite.All',
        'Group.ReadWrite.All',
        'User.Read.All',
        'Device.Read.All',
        'Directory.Read.All'
    )

    $context = Get-MgContext
    if ($null -ne $context) {
        $existingScopes = @($context.Scopes)
        $missingScopes = @($requiredScopes | Where-Object { $_ -notin $existingScopes })
        $hasDelegatedScopes = $missingScopes.Count -eq 0
        $contextAccount = [string](Get-SafeProperty -InputObject $context -Name 'Account')
        $contextAppName = [string](Get-SafeProperty -InputObject $context -Name 'AppName')
        $hasAppOnlyContext = -not [string]::IsNullOrWhiteSpace($contextAppName) -and [string]::IsNullOrWhiteSpace($contextAccount)

        if ($hasDelegatedScopes -or $hasAppOnlyContext) {
            $identity = if (-not [string]::IsNullOrWhiteSpace($contextAccount)) { $contextAccount } else { $contextAppName }
            Write-Log -Message "Using existing Microsoft Graph connection for '$identity'." -Level Info
            return
        }

        Write-Log -Message "Existing Microsoft Graph connection is missing delegated scope(s): $($missingScopes -join ', '). Reconnecting." -Level Warning
    }

    $methodQueue = @()
    switch ($AuthenticationMethod) {
        'Auto'        { $methodQueue = @('DeviceCode', 'Interactive') }
        'DeviceCode'  { $methodQueue = @('DeviceCode') }
        'Interactive' { $methodQueue = @('Interactive') }
        'Certificate' { $methodQueue = @('Certificate') }
    }

    while ($true) {
        foreach ($method in $methodQueue) {
            try {
                Connect-GraphOnce -RequiredScopes $requiredScopes -TenantIdValue $TenantIdValue -Method $method -ClientIdValue $ClientIdValue -CertificateThumbprintValue $CertificateThumbprintValue
                return
            }
            catch {
                Write-Log -Message "$method authentication failed: $($_.Exception.Message)" -Level Warning
            }
        }

        if ($NoInteractiveRetry) {
            throw 'Authentication failed and -NoInteractiveRetry is enabled.'
        }

        Write-Host ''
        Write-Log -Message 'Authentication did not complete. Choose how to continue.' -Level Action
        Write-Host '  1. Retry device-code authentication'
        Write-Host '  2. Use interactive browser authentication'
        Write-Host '  3. Use app-only certificate authentication'
        Write-Host '  4. Exit'
        $choice = Read-Host 'Select an option [1-4]'

        switch ($choice) {
            '1' { $methodQueue = @('DeviceCode') }
            '2' { $methodQueue = @('Interactive') }
            '3' {
                # These are local parameter variables, kept in scope for the lifetime of this single
                # Connect-GraphIfNeeded call, so they are only ever prompted for once even across retries.
                if ([string]::IsNullOrWhiteSpace($TenantIdValue)) { $TenantIdValue = Read-Host 'Tenant ID' }
                if ([string]::IsNullOrWhiteSpace($ClientIdValue)) { $ClientIdValue = Read-Host 'App registration client ID' }
                if ([string]::IsNullOrWhiteSpace($CertificateThumbprintValue)) { $CertificateThumbprintValue = Read-Host 'Certificate thumbprint' }
                $methodQueue = @('Certificate')
            }
            '4' { throw 'Authentication was not completed.' }
            default { Write-Log -Message 'Invalid selection. Please choose 1, 2, 3, or 4.' -Level Warning }
        }
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
            $null = Assert-GraphConnection -OperationName $OperationName
            return & $ScriptBlock
        }
        catch {
            $message = $_.Exception.Message
            $isRetryable = $message -match '(?i)(429|throttl|timeout|temporar|503|504|gateway|too many requests|service unavailable|try again)'

            if (-not $isRetryable -or $attempt -ge $MaximumAttempts) {
                # Surface full diagnostic detail (exception type name plus the full InnerException chain) on
                # the way out. Generic top-level messages like "Argument types do not match" are otherwise
                # nearly impossible to root-cause after the fact, since the SDK's real underlying error is
                # frequently wrapped several InnerException layers deep.
                # Level Warning (not Debug) is used deliberately here so this diagnostic detail is visible in
                # the console by default, without requiring -Verbose. This is precisely the information
                # needed to root-cause an opaque SDK error like "Argument types do not match" instead of
                # guessing at fixes.
                $exceptionTypeName = $_.Exception.GetType().FullName
                Write-Log -Message "$OperationName failed with a non-retryable error. Exception type: $exceptionTypeName. Message: $message" -Level Warning

                $innerException = $_.Exception.InnerException
                $innerDepth = 0
                while ($null -ne $innerException -and $innerDepth -lt 5) {
                    Write-Log -Message "  Inner exception [$innerDepth]: $($innerException.GetType().FullName): $($innerException.Message)" -Level Warning
                    $innerException = $innerException.InnerException
                    $innerDepth++
                }

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

    $null = Assert-GraphConnection -OperationName "resolve $Role"
    $groupProperties = @('id', 'displayName', 'groupTypes', 'membershipRule', 'securityEnabled', 'mailEnabled')

    if (Test-IsGuid -Value $GroupReference) {
        Write-Log -Message "Resolving $Role by object ID '$GroupReference'." -Level Info
        return Invoke-WithRetry -OperationName "Resolve $Role by object ID" -MaximumAttempts $RetryCount -DelaySeconds $RetryDelaySeconds -ScriptBlock {
            Get-MgGroup -GroupId $GroupReference -Property $groupProperties -ErrorAction Stop
        }
    }

    Write-Log -Message "Resolving $Role by exact display name '$GroupReference'." -Level Info
    $escapedName = ConvertTo-ODataStringLiteral -Value $GroupReference

    # Note: deliberately NOT named $matches. PowerShell variable names are case-insensitive, so
    # $matches is the same variable as the automatic $Matches populated by the -match operator.
    # Reusing that name here would silently shadow it for the rest of this function's scope.
    $matchingGroups = @(Invoke-WithRetry -OperationName "Resolve $Role by display name" -MaximumAttempts $RetryCount -DelaySeconds $RetryDelaySeconds -ScriptBlock {
        Get-MgGroup -Filter "displayName eq '$escapedName'" -All -Property $groupProperties -ErrorAction Stop
    })

    if ($matchingGroups.Count -eq 0) {
        return $null
    }

    if ($matchingGroups.Count -gt 1) {
        $duplicateSummary = $matchingGroups | ForEach-Object { "DisplayName='$($_.DisplayName)', Id='$($_.Id)'" }
        throw "$Role '$GroupReference' matched multiple groups. Re-run with the object ID. Matches: $($duplicateSummary -join '; ')"
    }

    return $matchingGroups[0]
}

function Wait-ForSourceUserGroup {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$InitialReference
    )

    $currentReference = $InitialReference

    while ($true) {
        if (Test-IsGuid -Value $currentReference) {
            $group = Resolve-EntraGroup -GroupReference $currentReference -Role 'Source user group'
            if ($null -ne $group) {
                return $group
            }
            throw "Source user group with object ID '$currentReference' was not found."
        }

        $group = Resolve-EntraGroup -GroupReference $currentReference -Role 'Source user group'
        if ($null -ne $group) {
            return $group
        }

        if ($NoInteractiveRetry) {
            throw "Source user group '$currentReference' was not found by exact display name. Create the group, add users, then re-run without -NoInteractiveRetry, or supply the object ID."
        }

        Write-Host ''
        Write-Log -Message "Source user group '$currentReference' was not found." -Level Action
        Write-Host ''
        Write-Host 'The source user group is a business-owned object. This script never creates it automatically.'
        Write-Host 'Required action:'
        Write-Host '  1. Create the Microsoft Entra security group.'
        Write-Host '  2. Add one or more users to it.'
        Write-Host '  3. Allow a moment for Microsoft Entra ID replication.'
        Write-Host ''
        $newReference = Read-Host 'Enter the source user group display name or object ID to retry'
        if (-not [string]::IsNullOrWhiteSpace($newReference)) {
            $currentReference = $newReference
        }
    }
}

function New-TargetDeviceGroup {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DisplayName
    )

    if ($DisplayName.Length -gt 120) {
        throw "Group display name '$DisplayName' exceeds the 120 character limit supported by Microsoft Entra ID."
    }

    $mailNickname = ($DisplayName -replace '[^a-zA-Z0-9]', '')
    if ([string]::IsNullOrWhiteSpace($mailNickname)) {
        $mailNickname = 'DeviceGroup' + (Get-Random -Minimum 1000 -Maximum 9999)
    }
    if ($mailNickname.Length -gt 64) {
        $mailNickname = $mailNickname.Substring(0, 64)
    }

    $groupParameters = @{
        DisplayName     = $DisplayName
        MailEnabled     = $false
        MailNickname    = $mailNickname
        SecurityEnabled = $true
        GroupTypes      = @()
        Description     = 'Created automatically by Sync-UserGroupDevicesToDeviceGroup.ps1 as a target device security group.'
    }

    if (-not $PSCmdlet.ShouldProcess($DisplayName, 'Create target device security group')) {
        return $null
    }

    $newGroup = Invoke-WithRetry -OperationName "Create target device group '$DisplayName'" -MaximumAttempts $RetryCount -DelaySeconds $RetryDelaySeconds -ScriptBlock {
        New-MgGroup @groupParameters -ErrorAction Stop
    }

    Write-Log -Message "Created target device group '$($newGroup.DisplayName)' [$($newGroup.Id)]." -Level Success
    return $newGroup
}

function Wait-ForTargetDeviceGroup {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$InitialReference
    )

    $currentReference = $InitialReference

    while ($true) {
        if ([string]::IsNullOrWhiteSpace($currentReference)) {
            if ($NoInteractiveRetry) {
                throw 'A target device group name or object ID is required. Supply -TargetDeviceGroup or -TargetDeviceGroupId, or omit -NoInteractiveRetry so the script can prompt for one.'
            }

            Write-Host ''
            Write-Log -Message 'No target device group was specified.' -Level Action
            $currentReference = Read-Host 'Enter the target device group display name or object ID'
            continue
        }

        if (Test-IsGuid -Value $currentReference) {
            $group = Resolve-EntraGroup -GroupReference $currentReference -Role 'Target device group'
            if ($null -ne $group) {
                return $group
            }
            throw "Target device group with object ID '$currentReference' was not found. A new group cannot be created with a specific object ID."
        }

        $group = Resolve-EntraGroup -GroupReference $currentReference -Role 'Target device group'
        if ($null -ne $group) {
            return $group
        }

        if ($NoInteractiveRetry) {
            throw "Target device group '$currentReference' was not found. Create it beforehand or re-run without -NoInteractiveRetry so the script can offer to create it."
        }

        Write-Host ''
        Write-Log -Message "Target device group '$currentReference' was not found." -Level Action
        Write-Host ''
        Write-Host 'Choose how to continue:'
        Write-Host '  1. Create this device group automatically (recommended)'
        Write-Host '  2. Enter a different display name or object ID'
        Write-Host '  3. Exit'
        $choice = Read-Host 'Select an option [1-3]'

        switch ($choice) {
            '1' {
                $createdGroup = $null
                try {
                    $createdGroup = New-TargetDeviceGroup -DisplayName $currentReference
                }
                catch {
                    Write-Log -Message "Failed to create target device group '$currentReference': $($_.Exception.Message)" -Level Error
                    Write-Host 'This is commonly caused by insufficient Graph permissions (Group.ReadWrite.All) or a display name/mail nickname conflict.'
                    Write-Host 'Choose option 1 to retry, option 2 to try a different name, or option 3 to exit and resolve the issue manually.'
                    continue
                }

                if ($null -eq $createdGroup) {
                    # New-TargetDeviceGroup returns $null only when -WhatIf suppressed the actual creation.
                    # That is expected simulation behavior, not a failure, so it gets its own clear message
                    # instead of being routed through the generic creation-failure handling above.
                    Write-Host ''
                    Write-Log -Message "Group creation was simulated because -WhatIf is in effect; no group named '$currentReference' actually exists yet." -Level Warning
                    Write-Host 'Choose option 2 to point at an existing group, or option 3 to exit and re-run without -WhatIf to create it for real.'
                    continue
                }

                try {
                    Write-Log -Message 'Waiting 30 second(s) for Microsoft Entra ID replication before continuing.' -Level Info
                    Start-Sleep -Seconds 30

                    $confirmedGroup = $null
                    for ($attempt = 1; $attempt -le 5; $attempt++) {
                        $confirmedGroup = Resolve-EntraGroup -GroupReference $createdGroup.Id -Role 'Target device group'
                        if ($null -ne $confirmedGroup) {
                            break
                        }
                        Write-Log -Message "Newly created group not yet visible. Waiting additional 10 second(s) (attempt $attempt of 5)." -Level Warning
                        Start-Sleep -Seconds 10
                    }

                    if ($null -eq $confirmedGroup) {
                        throw "Target device group '$($createdGroup.DisplayName)' [$($createdGroup.Id)] was created but could not be confirmed via Get-MgGroup after the replication delay. It likely exists; re-run the script and it should resolve normally now that more time has passed."
                    }

                    return $confirmedGroup
                }
                catch {
                    Write-Log -Message "Group creation succeeded but post-creation validation failed: $($_.Exception.Message)" -Level Error
                    Write-Host 'Press any key to retry validation, or restart the script and supply the same name to pick the group back up.'
                    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
                }
            }
            '2' {
                $newReference = Read-Host 'Enter the target device group display name or object ID'
                if (-not [string]::IsNullOrWhiteSpace($newReference)) {
                    $currentReference = $newReference
                }
            }
            '3' { throw 'Target device group resolution was cancelled by the operator.' }
            default { Write-Log -Message 'Invalid selection. Please choose 1, 2, or 3.' -Level Warning }
        }
    }
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
        Write-Log -Message "Target group '$($Group.DisplayName)' is not marked securityEnabled. Device assignments typically require a security-enabled group." -Level Warning
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
        $rawMembers = @(Invoke-WithRetry -OperationName 'Get transitive source group members' -MaximumAttempts $RetryCount -DelaySeconds $RetryDelaySeconds -ScriptBlock {
            Get-MgGroupTransitiveMember -GroupId $GroupId -All -ConsistencyLevel eventual -Property $memberProperties -ErrorAction Stop
        })
    }
    else {
        Write-Log -Message 'Retrieving direct source group members.' -Level Info
        $rawMembers = @(Invoke-WithRetry -OperationName 'Get direct source group members' -MaximumAttempts $RetryCount -DelaySeconds $RetryDelaySeconds -ScriptBlock {
            Get-MgGroupMember -GroupId $GroupId -All -Property $memberProperties -ErrorAction Stop
        })
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

function Wait-ForSourceUsers {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$SourceGroup,

        [Parameter(Mandatory = $true)]
        [bool]$Transitive
    )

    while ($true) {
        $users = @(Get-UserMembersFromGroup -GroupId $SourceGroup.Id -Transitive $Transitive)
        if ($users.Count -gt 0) {
            return $users
        }

        if ($NoInteractiveRetry) {
            throw "Source user group '$($SourceGroup.DisplayName)' contains no user members."
        }

        Write-Host ''
        Write-Log -Message "Source user group '$($SourceGroup.DisplayName)' exists but contains no user members." -Level Action
        Write-Host 'Add one or more users to the source group, wait for replication if needed, then press any key to retry.'
        $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
    }
}

function Get-UserDeviceObjects {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $User,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Registered', 'Owned', 'Both')]
        [string]$RelationshipMode
    )

    # DIAGNOSTIC INSTRUMENTATION:
    # This function's entire body is wrapped in try/catch below. The error PowerShell has been reporting
    # ("Argument types do not match", attributed to [Get-UserDeviceObjects] rather than to
    # Get-MgUserRegisteredDevice/Get-MgUserOwnedDevice directly) indicates the terminating error is most
    # likely NOT originating inside those two Graph cmdlet calls, since PowerShell normally attributes a
    # terminating error to the innermost command that threw it. Two prior hypotheses (a [pscustomobject]
    # parameter-type conflict, then a -Property argument conflict) were tested and neither stopped the
    # recurrence at this same call site, which means guessing a third specific line is not responsible
    # without hard evidence. This wrapper captures the full exception type, PowerShell's ScriptStackTrace
    # (which pinpoints the exact failing line/command inside this function), the exact CategoryInfo, and
    # every layer of InnerException, then surfaces all of it at Warning level (visible without -Verbose)
    # before rethrowing, so the *next* run tells us definitively where this is coming from.
    try {
        $results = New-Object System.Collections.Generic.List[object]

        if ($RelationshipMode -in @('Registered', 'Both')) {
            $registeredDevices = @(Invoke-WithRetry -OperationName "Get registered devices for user '$($User.Id)'" -MaximumAttempts $RetryCount -DelaySeconds $RetryDelaySeconds -ScriptBlock {
                Get-MgUserRegisteredDevice -UserId $User.Id -All -ErrorAction Stop
            })

            foreach ($device in $registeredDevices) {
                $results.Add([pscustomobject]@{ Relationship = 'Registered'; Device = $device })
            }
        }

        if ($RelationshipMode -in @('Owned', 'Both')) {
            $ownedDevices = @(Invoke-WithRetry -OperationName "Get owned devices for user '$($User.Id)'" -MaximumAttempts $RetryCount -DelaySeconds $RetryDelaySeconds -ScriptBlock {
                Get-MgUserOwnedDevice -UserId $User.Id -All -ErrorAction Stop
            })

            foreach ($device in $ownedDevices) {
                $results.Add([pscustomobject]@{ Relationship = 'Owned'; Device = $device })
            }
        }

        # CONFIRMED ROOT CAUSE (from live ScriptStackTrace + .NET StackTrace evidence):
        # "return @($results)" was throwing System.ArgumentException: Argument types do not match, with a
        # .NET stack showing System.Linq.Expressions.Expression.Condition inside
        # PSEnumerableBinder.MaybeDebase / PSToObjectArrayBinder.Bind. This is a documented Windows
        # PowerShell 5.1 dynamic-binder defect: wrapping a strongly typed System.Collections.Generic.List<T>
        # with the @() array-subexpression operator can fail this way (most reliably reproduced when the
        # list is empty or has exactly one element, which is why it hit on the very first user processed).
        # .ToArray() returns a concrete object[] directly from the List<T> without going through that
        # dynamic binder path at all, sidestepping the defect entirely rather than working around a symptom.
        return $results.ToArray()
    }
    catch {
        Write-Log -Message "=== DIAGNOSTIC: Get-UserDeviceObjects failed for user '$($User.Id)' / '$($User.UserPrincipalName)' ===" -Level Warning
        Write-Log -Message "Exception type: $($_.Exception.GetType().FullName)" -Level Warning
        Write-Log -Message "Exception message: $($_.Exception.Message)" -Level Warning
        Write-Log -Message "CategoryInfo: $($_.CategoryInfo.ToString())" -Level Warning
        Write-Log -Message "FullyQualifiedErrorId: $($_.FullyQualifiedErrorId)" -Level Warning
        Write-Log -Message "ScriptStackTrace (pinpoints the exact failing line inside this function):" -Level Warning
        Write-Log -Message $_.ScriptStackTrace -Level Warning
        if (-not [string]::IsNullOrWhiteSpace($_.Exception.StackTrace)) {
            Write-Log -Message ".NET StackTrace: $($_.Exception.StackTrace)" -Level Warning
        }

        $innerException = $_.Exception.InnerException
        $innerDepth = 0
        while ($null -ne $innerException -and $innerDepth -lt 5) {
            Write-Log -Message "Inner exception [$innerDepth]: $($innerException.GetType().FullName): $($innerException.Message)" -Level Warning
            $innerException = $innerException.InnerException
            $innerDepth++
        }
        Write-Log -Message '=== END DIAGNOSTIC ===' -Level Warning

        throw
    }
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
        # Intentionally untyped: see the note in Get-UserDeviceObjects about the [pscustomobject]
        # parameter-type binding issue on Windows PowerShell 5.1.
        $User
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

function Get-TargetGroupDeviceMembers {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$GroupId
    )

    # -Property intentionally omitted here for the same reason documented in Get-UserDeviceObjects: the
    # target group's members are returned as polymorphic directoryObject instances, and requesting
    # device-specific field names (deviceId, operatingSystem, trustType, etc.) against that base type has
    # been observed to throw "Argument types do not match" on some SDK versions. All fields are still read
    # safely afterward via Get-GraphObjectValue, which reads from AdditionalProperties regardless.
    Write-Log -Message 'Retrieving current target group members.' -Level Info
    $rawMembers = @(Invoke-WithRetry -OperationName 'Get target group members' -MaximumAttempts $RetryCount -DelaySeconds $RetryDelaySeconds -ScriptBlock {
        Get-MgGroupMember -GroupId $GroupId -All -ErrorAction Stop
    })

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
        # Intentionally untyped: see the note in Get-UserDeviceObjects about the [pscustomobject]
        # parameter-type binding issue on Windows PowerShell 5.1.
        $DeviceRecord,

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
        # Intentionally untyped: see the note in Get-UserDeviceObjects about the [pscustomobject]
        # parameter-type binding issue on Windows PowerShell 5.1.
        $DeviceRecord
    )

    $odataId = "https://graph.microsoft.com/v1.0/directoryObjects/$($DeviceRecord.Id)"

    Invoke-WithRetry -OperationName "Add device '$($DeviceRecord.Id)' to target group" -MaximumAttempts $RetryCount -DelaySeconds $RetryDelaySeconds -ScriptBlock {
        New-MgGroupMemberByRef -GroupId $GroupId -OdataId $odataId -ErrorAction Stop
    } | Out-Null
}

function Remove-DeviceFromGroup {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$GroupId,

        [Parameter(Mandatory = $true)]
        # Intentionally untyped: see the note in Get-UserDeviceObjects about the [pscustomobject]
        # parameter-type binding issue on Windows PowerShell 5.1.
        $DeviceRecord
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
    Write-Log -Message "$script:ScriptName version $script:ScriptVersion starting. PowerShell version $($PSVersionTable.PSVersion)." -Level Info

    Import-RequiredGraphModules -InstallIfMissing:$InstallMissingModules

    # Print the exact loaded module versions. This is directly relevant to the "Argument types do not
    # match" investigation, since SDK behavior around registeredDevices/ownedDevices navigation properties
    # is known to differ across Microsoft.Graph module releases.
    foreach ($moduleName in @('Microsoft.Graph.Authentication', 'Microsoft.Graph.Users', 'Microsoft.Graph.Groups', 'Microsoft.Graph.Identity.DirectoryManagement')) {
        $loadedModule = Get-Module -Name $moduleName | Select-Object -First 1
        if ($null -ne $loadedModule) {
            Write-Log -Message "Loaded module in this session: $moduleName version $($loadedModule.Version)" -Level Info
        }
    }

    Connect-GraphIfNeeded -TenantIdValue $TenantId -ClientIdValue $ClientId -CertificateThumbprintValue $CertificateThumbprint -SkipConnect:$SkipGraphConnect

    if ($PSCmdlet.ParameterSetName -eq 'ById') {
        $sourceGroupReference = $SourceUserGroupId
        $targetGroupReference = $TargetDeviceGroupId
    }
    else {
        $sourceGroupReference = $SourceUserGroup
        $targetGroupReference = $TargetDeviceGroup
    }

    # The source user group is business-owned and must already exist; the script never creates it.
    $sourceGroup = Wait-ForSourceUserGroup -InitialReference $sourceGroupReference

    # The target device group is optional. If it does not exist, the operator is offered the
    # choice to have the script create it automatically, then the script waits for replication.
    $targetGroup = Wait-ForTargetDeviceGroup -InitialReference $targetGroupReference

    Test-StaticSecurityGroup -Group $sourceGroup -Role 'Source user group'
    Test-StaticSecurityGroup -Group $targetGroup -Role 'Target device group'

    Write-Log -Message "Source user group: '$($sourceGroup.DisplayName)' [$($sourceGroup.Id)]" -Level Success
    Write-Log -Message "Target device group: '$($targetGroup.DisplayName)' [$($targetGroup.Id)]" -Level Success
    Write-Log -Message "Device relationship mode: $DeviceRelationship" -Level Info
    Write-Log -Message "Use transitive members: $UseTransitiveMembers" -Level Info
    Write-Log -Message "Remove stale devices: $RemoveStaleDevices" -Level Info

    $sourceUsers = @(Wait-ForSourceUsers -SourceGroup $sourceGroup -Transitive $UseTransitiveMembers)
    $desiredDevices = [ordered]@{}
    $processedUsers = 0
    $rawDeviceRelationshipCount = 0
    $acceptedDeviceRelationshipCount = 0
    $usersWithoutDevices = New-Object System.Collections.Generic.List[object]

    foreach ($user in $sourceUsers) {
        $processedUsers++
        $userLabel = if (-not [string]::IsNullOrWhiteSpace($user.UserPrincipalName)) { $user.UserPrincipalName } elseif (-not [string]::IsNullOrWhiteSpace($user.DisplayName)) { $user.DisplayName } else { $user.Id }
        Write-Progress -Activity 'Resolving user devices' -Status $userLabel -PercentComplete (($processedUsers / [Math]::Max(1, $sourceUsers.Count)) * 100)

        $userDeviceObjects = @(Get-UserDeviceObjects -User $user -RelationshipMode $DeviceRelationship)
        $rawDeviceRelationshipCount += $userDeviceObjects.Count
        $acceptedForUser = 0

        foreach ($userDeviceObject in $userDeviceObjects) {
            $added = Add-DesiredDeviceRecord -DesiredDevices $desiredDevices -Device $userDeviceObject.Device -Relationship $userDeviceObject.Relationship -User $user
            if ($added) {
                $acceptedDeviceRelationshipCount++
                $acceptedForUser++
            }
        }

        if ($acceptedForUser -eq 0) {
            $usersWithoutDevices.Add([pscustomobject]@{
                UserObjectId       = $user.Id
                DisplayName        = $user.DisplayName
                UserPrincipalName  = $user.UserPrincipalName
                Mail               = $user.Mail
                RelationshipMode   = $DeviceRelationship
                Reason             = 'No associated devices matched the selected relationship and filter criteria'
            })
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
    Write-Log -Message "Users without accepted devices: $($usersWithoutDevices.Count)" -Level Info
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

        if ($usersWithoutDevices.Count -gt 0) {
            $reportBaseName = [System.IO.Path]::GetFileNameWithoutExtension($ReportPath)
            $reportExtension = [System.IO.Path]::GetExtension($ReportPath)
            if ([string]::IsNullOrWhiteSpace($reportExtension)) { $reportExtension = '.csv' }
            $usersWithoutDevicesPath = Join-Path -Path (Split-Path -Path $ReportPath -Parent) -ChildPath ("$reportBaseName-UsersWithoutDevices$reportExtension")
            $usersWithoutDevices | Sort-Object UserPrincipalName, DisplayName | Export-Csv -Path $usersWithoutDevicesPath -NoTypeInformation -Encoding UTF8
            Write-Log -Message "Users without devices report written to '$usersWithoutDevicesPath'." -Level Success
        }
    }

    Write-Log -Message 'Synchronization completed.' -Level Success
    Write-Log -Message "Summary: users=$($sourceUsers.Count); usersWithoutDevices=$($usersWithoutDevices.Count); desiredDevices=$($desiredDevices.Count); currentDevices=$($currentDevices.Count); add=$($deviceIdsToAdd.Count); remove=$($deviceIdsToRemove.Count); reportRows=$($reportRows.Count)." -Level Success
}
catch {
    Write-Log -Message $_.Exception.Message -Level Error
    throw
}
finally {
    # Runs on both the success path and the error/throw path above, so the Graph session is always
    # cleaned up on exit rather than only after a fully successful run.
    if ($SkipGraphConnect) {
        # This script never established the connection in the first place (the caller brought their own
        # via -SkipGraphConnect), so it is not this script's place to tear it down either.
        Write-Log -Message 'Skipping Microsoft Graph disconnect because -SkipGraphConnect was specified; the connection was not established by this script.' -Level Info
    }
    else {
        try {
            $finalContext = Get-MgContext
            if ($null -ne $finalContext) {
                Disconnect-MgGraph -ErrorAction Stop | Out-Null
                Write-Log -Message 'Disconnected from Microsoft Graph.' -Level Info
            }
        }
        catch {
            # Best-effort cleanup only. A failure here (for example, the session was already gone) should
            # never mask or replace the original success/error result of the script itself.
            Write-Log -Message "Could not cleanly disconnect from Microsoft Graph: $($_.Exception.Message)" -Level Warning
        }
    }
}
