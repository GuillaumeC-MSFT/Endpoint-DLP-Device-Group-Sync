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
  Note: interactive browser sign-in depends on the Windows WAM broker (mandatory since Microsoft.Graph
  PowerShell SDK 2.34.0) and can silently hang with no visible window when PowerShell is running elevated
  or under a different user context. Device code authentication is the most reliable option in that case.
- Validates the Microsoft Graph context before Graph operations to avoid hidden re-authentication surprises.
- Uses accessibility-friendly text status labels instead of relying only on console colors.
- Disconnects the Microsoft Graph session automatically when the script finishes, whether it completed
  successfully or failed, unless -SkipGraphConnect was used (in which case the connection was supplied by
  the caller and is left untouched).
- Automatically detects and installs any missing required Microsoft.Graph module and loads it in the same
  run, with no prior knowledge needed of whether it is already present, and without needing to close and
  reopen PowerShell. This is done by default; nothing needs to be specified for it to happen. Installation
  reads the freshly installed module's location directly from PowerShellGet rather than relying on
  PowerShell's module autodiscovery cache, which is what historically made a restart necessary. Pass
  -InstallMissingModules:$false to disable this and fail fast instead if a module is missing. A new
  PowerShell session is only genuinely required if a different, conflicting version of a required module
  was already loaded into the current session before this script ran (a .NET assembly-loading limitation
  in Windows PowerShell 5.1) - in that specific case the script reports it clearly instead of failing
  silently.

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
    -AuthenticationMethod DeviceCode

.EXAMPLE
# Missing required modules are detected and installed automatically by default; no switch is needed.
# Use -InstallMissingModules:$false only if you specifically want the script to fail instead of installing.
.\Sync-UserGroupDevicesToDeviceGroup.ps1 `
    -SourceUserGroup "All Field Users" `
    -TargetDeviceGroup "All Field User Devices" `
    -InstallMissingModules:$false

.NOTES
Script version: 3.16.0

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
    [switch]$InstallMissingModules = $true,

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

$script:ScriptVersion = '3.16.0'
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

function Get-FreshlyInstalledModuleInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ModuleName
    )

    # WHY THIS EXISTS: immediately after Install-Module completes, a plain "Get-Module -ListAvailable" in
    # the SAME PowerShell session can still fail to see the module that was just written to disk. This is a
    # long-standing Windows PowerShell 5.1 behavior: module autodiscovery relies on an internal path/manifest
    # cache that is only guaranteed to be rebuilt on next session start, which is exactly why a restart has
    # historically been "required" after installing a missing module. Get-InstalledModule (from PowerShellGet,
    # which tracks its own independent inventory of what it has installed rather than relying on that cache)
    # reliably reflects installations from moments ago in the same session, including the exact on-disk
    # location. Importing directly from that location's manifest bypasses the stale-cache problem entirely.
    $installedModuleInfo = $null
    try {
        $installedModuleInfo = Get-InstalledModule -Name $ModuleName -ErrorAction Stop | Sort-Object Version -Descending | Select-Object -First 1
    }
    catch {
        $installedModuleInfo = $null
    }

    if ($null -ne $installedModuleInfo -and -not [string]::IsNullOrWhiteSpace([string]$installedModuleInfo.InstalledLocation) -and (Test-Path -Path $installedModuleInfo.InstalledLocation)) {
        $manifestPath = Join-Path -Path $installedModuleInfo.InstalledLocation -ChildPath "$ModuleName.psd1"
        if (Test-Path -Path $manifestPath) {
            return [pscustomobject]@{ Version = $installedModuleInfo.Version; ManifestPath = $manifestPath }
        }
    }

    # Fallback if PowerShellGet/Get-InstalledModule is unavailable for some reason: re-scan the normal way.
    # This may still hit the stale-cache issue described above in rare environments, but it is a reasonable
    # last resort rather than failing outright.
    $availableModule = Get-Module -ListAvailable -Name $ModuleName | Sort-Object Version -Descending | Select-Object -First 1
    if ($null -ne $availableModule) {
        return [pscustomobject]@{ Version = $availableModule.Version; ManifestPath = $availableModule.Path }
    }

    return $null
}

function Initialize-NuGetProviderForCurrentUser {
    [CmdletBinding()]
    param()

    # WHY THIS EXISTS: Install-Module correctly honors -Scope CurrentUser for the module itself, but if the
    # underlying NuGet package provider has never been registered on this machine, Install-Module first has
    # to silently bootstrap it - and that bootstrap step has a long-standing PackageManagement bug where it
    # can attempt an all-users install regardless of the scope requested for the module, surfacing as
    # "Administrator rights are required to install or update" even when -Scope CurrentUser was specified
    # (confirmed in PowerShell/PowerShell GitHub issue #12777, reproduced even by users who genuinely are
    # administrators). Explicitly installing the NuGet provider for CurrentUser scope first means
    # Install-Module never needs to trigger that bootstrap path at all.
    $nugetProvider = Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue | Sort-Object Version -Descending | Select-Object -First 1
    if ($null -ne $nugetProvider) {
        return
    }

    Write-Log -Message 'NuGet package provider was not found. Installing it for the current user first (this avoids a known PackageManagement bug where module installation can otherwise demand administrator rights even with -Scope CurrentUser).' -Level Info

    try {
        # Some older/locked-down environments require TLS 1.2 to be explicitly enabled to reach
        # PowerShell Gallery / nuget.org; this is a safe, additive setting for the current process only.
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    }
    catch {
        # Non-fatal: if this specific enum value or property is unavailable on this platform/version, the
        # subsequent provider install is still attempted as-is.
    }

    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Scope CurrentUser -Force -ErrorAction Stop | Out-Null
    Write-Log -Message 'NuGet package provider installed for the current user.' -Level Success
}

function Get-DedicatedModuleCachePath {
    [CmdletBinding()]
    param()

    # A location deliberately NOT under Documents. Install-Module's default CurrentUser destination lives
    # under the Documents special folder, which is exactly the location most commonly affected by OneDrive
    # Known Folder redirection and by Windows Defender Controlled Folder Access - both of which are
    # documented, real-world causes of Install-Module failing with a misleading "Administrator rights are
    # required" message even when -Scope CurrentUser is specified and the account genuinely is an admin
    # (see PowerShellGetv2 GitHub issue #586, and multiple independently reported cases with this exact
    # error text). LOCALAPPDATA is not subject to either of those by default, so using it as a fallback
    # install destination sidesteps this entire failure class rather than guessing at the specific cause.
    if (-not [string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
        return Join-Path -Path $env:LOCALAPPDATA -ChildPath 'Sync-UserGroupDevicesToDeviceGroup\Modules'
    }

    return Join-Path -Path $HOME -ChildPath '.sync-usergroupdevicestodevicegroup/modules'
}

function Test-PathIsWritable {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    try {
        if (-not (Test-Path -Path $Path)) {
            New-Item -ItemType Directory -Path $Path -Force -ErrorAction Stop | Out-Null
        }

        $testFilePath = Join-Path -Path $Path -ChildPath ".write-test-$([Guid]::NewGuid().ToString('N')).tmp"
        [System.IO.File]::WriteAllText($testFilePath, 'test')
        Remove-Item -Path $testFilePath -Force -ErrorAction SilentlyContinue
        return $true
    }
    catch {
        return $false
    }
}

function Write-ModuleInstallDiagnostics {
    [CmdletBinding()]
    param()

    # Hard, verifiable facts about this environment, logged once up front - not a theory, just the actual
    # state of the machine, so that if automatic installation still fails after the fallbacks below, there
    # is real evidence to work from instead of another guess.
    Write-Log -Message "PSModulePath: $env:PSModulePath" -Level Info

    try {
        $documentsPath = [Environment]::GetFolderPath('MyDocuments')
        Write-Log -Message "Documents special folder resolves to: $documentsPath" -Level Info
        if ($documentsPath -match '(?i)onedrive') {
            Write-Log -Message 'Documents folder appears to be redirected into OneDrive. This is a known, documented cause of Install-Module -Scope CurrentUser failing with a misleading "Administrator rights are required" message (PowerShellGetv2 GitHub issue #586).' -Level Warning
        }
        $documentsWritable = Test-PathIsWritable -Path $documentsPath
        Write-Log -Message "Documents folder is writable by this process: $documentsWritable" -Level Info
    }
    catch {
        Write-Log -Message "Could not determine or test the Documents special folder: $($_.Exception.Message)" -Level Info
    }

    $powerShellGetModule = Get-Module -ListAvailable -Name PowerShellGet | Sort-Object Version -Descending | Select-Object -First 1
    if ($null -ne $powerShellGetModule) {
        Write-Log -Message "PowerShellGet module version available: $($powerShellGetModule.Version)" -Level Info
    }

    $psResourceGetAvailable = $null -ne (Get-Module -ListAvailable -Name Microsoft.PowerShell.PSResourceGet | Select-Object -First 1)
    Write-Log -Message "Microsoft.PowerShell.PSResourceGet (Install-PSResource) available: $psResourceGetAvailable" -Level Info

    $cfaStatus = Test-ControlledFolderAccessStatus
    switch ($cfaStatus) {
        1 {
            # CONFIRMED, NOT A THEORY: Controlled Folder Access blocks writes from processes that are not
            # explicitly allow-listed, independently of whether that process is running elevated/as
            # Administrator. This is precisely why running as admin does not help - CFA is a separate
            # control from UAC/admin rights entirely. It commonly manifests as a module folder that gets
            # partially written (for example, the .psd1 manifest succeeds but a .format.ps1xml or .dll file
            # inside the same folder is silently blocked), which then looks "installed" to Get-Module
            # -ListAvailable while actually being corrupted and incomplete.
            Write-Log -Message 'Windows Defender Controlled Folder Access is ENABLED on this machine. If module installation fails or a module fails to load with a "Could not find file" error pointing at a file inside an existing module version folder, this is almost certainly the cause - CFA can silently block individual file writes during installation regardless of admin rights.' -Level Warning
            $currentHostExecutableName = if ($PSVersionTable.PSEdition -eq 'Core') { 'pwsh.exe' } else { 'powershell.exe' }
            $currentHostExecutablePath = Join-Path -Path $PSHOME -ChildPath $currentHostExecutableName
            Write-Log -Message "Remediation: open Windows Security > Virus & threat protection > Manage ransomware protection > Controlled folder access > Allow an app through Controlled folder access, and add $currentHostExecutableName (full path: $currentHostExecutablePath). Alternatively, temporarily turn Controlled folder access Off, install the modules, then turn it back on. If this machine is managed by your organization, your security/Intune administrator may need to add this exclusion instead." -Level Action
        }
        2 {
            Write-Log -Message 'Windows Defender Controlled Folder Access is in AUDIT mode on this machine (blocks are logged but not enforced). This should not block installation, but if problems persist, check the Windows Defender event log for Controlled Folder Access audit entries.' -Level Info
        }
        0 {
            Write-Log -Message 'Windows Defender Controlled Folder Access is disabled on this machine.' -Level Info
        }
        default {
            # $null: could not be determined (non-Windows, Defender not present, or the cmdlet is
            # unavailable). Nothing actionable to report.
        }
    }
}

function Get-FullErrorDetailText {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    # PowerShellGet/PackageManagement cmdlets (Install-Module, Save-Module, Find-Module) are known to throw
    # generic top-level wrapper messages such as "Unable to save the module 'X'." or "Unable to resolve
    # package source" while the actual, specific, actionable cause lives in .ErrorDetails.Message or several
    # layers deep in .InnerException. Logging only $_.Exception.Message (as an earlier version of this
    # script did) silently discards that detail. This collects everything available on the ErrorRecord so
    # the real cause is visible, whatever it turns out to be, instead of guessing at it.
    $lines = New-Object System.Collections.Generic.List[string]

    $lines.Add("Exception type: $($ErrorRecord.Exception.GetType().FullName)")
    $lines.Add("Message: $($ErrorRecord.Exception.Message)")

    if ($null -ne $ErrorRecord.ErrorDetails -and -not [string]::IsNullOrWhiteSpace($ErrorRecord.ErrorDetails.Message)) {
        $lines.Add("ErrorDetails: $($ErrorRecord.ErrorDetails.Message)")
    }

    if ($null -ne $ErrorRecord.CategoryInfo) {
        $lines.Add("CategoryInfo: $($ErrorRecord.CategoryInfo.ToString())")
    }

    if (-not [string]::IsNullOrWhiteSpace($ErrorRecord.FullyQualifiedErrorId)) {
        $lines.Add("FullyQualifiedErrorId: $($ErrorRecord.FullyQualifiedErrorId)")
    }

    if ($null -ne $ErrorRecord.TargetObject) {
        $lines.Add("TargetObject: $($ErrorRecord.TargetObject)")
    }

    $innerException = $ErrorRecord.Exception.InnerException
    $innerDepth = 0
    while ($null -ne $innerException -and $innerDepth -lt 6) {
        $lines.Add("Inner exception [$innerDepth]: $($innerException.GetType().FullName): $($innerException.Message)")
        $innerException = $innerException.InnerException
        $innerDepth++
    }

    return ($lines -join ' | ')
}

function Test-PSGalleryReachableAndTrusted {
    [CmdletBinding()]
    param()

    # Separates "we cannot reach or use PSGallery at all" (a repository/network/trust problem, same for
    # every module) from "we reached PSGallery fine but this specific save/install step failed" (a
    # destination/dependency/file problem, specific to one module or one folder). Surfacing this distinction
    # up front means the eventual error message points at the right category of thing to fix.
    try {
        $repository = Get-PSRepository -Name PSGallery -ErrorAction Stop
        Write-Log -Message "PSGallery repository registered. InstallationPolicy: $($repository.InstallationPolicy)" -Level Info

        if ($repository.InstallationPolicy -ne 'Trusted') {
            try {
                Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop
                Write-Log -Message 'Set PSGallery InstallationPolicy to Trusted for this session to avoid an unattended confirmation prompt blocking installation.' -Level Info
            }
            catch {
                Write-Log -Message "Could not set PSGallery to Trusted: $($_.Exception.Message). Installation will still be attempted with -Force, which normally bypasses this prompt on its own." -Level Warning
            }
        }
    }
    catch {
        Write-Log -Message "PSGallery repository is not registered or could not be queried: $($_.Exception.Message). Attempting to register it." -Level Warning
        try {
            Register-PSRepository -Default -ErrorAction Stop
            Write-Log -Message 'Registered the default PSGallery repository.' -Level Success
        }
        catch {
            Write-Log -Message "Could not register PSGallery: $($_.Exception.Message)" -Level Warning
        }
    }

    try {
        $null = Find-Module -Name Microsoft.Graph.Authentication -Repository PSGallery -ErrorAction Stop
        Write-Log -Message 'Confirmed PSGallery is reachable and can resolve packages (Find-Module succeeded).' -Level Info
        return $true
    }
    catch {
        Write-Log -Message "Find-Module against PSGallery failed: $(Get-FullErrorDetailText -ErrorRecord $_). This points to a network, proxy, or repository-registration problem rather than a problem with a specific module or destination folder." -Level Warning
        return $false
    }
}

function Remove-ExistingModuleCacheEntry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ModuleName,

        [Parameter(Mandatory = $true)]
        [string]$DedicatedCachePath,

        [Parameter()]
        [string]$Reason = 'starting a clean installation attempt'
    )

    # EVIDENCE THIS EXISTS TO ADDRESS: a confirmed real failure showed Install-PSResource/Save-PSResource
    # (ATTEMPT 3) throwing System.Management.Automation.CommandNotFoundException /
    # Microsoft.PowerShell.Commands.ImportModuleCommand, reporting "Could not find file
    # '...\<ModuleName>\<Version>\<ModuleName>.format.ps1xml'" - i.e. a partially extracted, corrupted
    # module folder already sitting in the dedicated cache, missing one of its required files. The most
    # likely origin is Save-Module (ATTEMPT 2) partially writing files before failing with
    # ProviderFailToDownloadFile and this script previously breaking out of that attempt without cleaning up
    # what it had already written. Rather than trying to precisely diagnose which specific file ends up
    # missing or exactly which prior attempt left it behind, this removes the module's own folder (across
    # all versions) from the dedicated cache before each fresh install attempt, so every attempt always
    # starts from a genuinely clean slate. This is scoped strictly to "<DedicatedCachePath>\<ModuleName>",
    # never touching anything outside this script's own private cache folder.
    $moduleCachePath = Join-Path -Path $DedicatedCachePath -ChildPath $ModuleName
    if (Test-Path -Path $moduleCachePath) {
        Write-Log -Message "Removing existing cached copy of '$ModuleName' at '$moduleCachePath' before $Reason (this may be an incomplete/corrupted leftover from an earlier failed attempt)." -Level Info
        try {
            Remove-Item -Path $moduleCachePath -Recurse -Force -ErrorAction Stop
            return $true
        }
        catch {
            Write-Log -Message "Could not remove '$moduleCachePath': $($_.Exception.Message)" -Level Warning
            return $false
        }
    }

    return $true
}

function Install-RequiredGraphModule {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ModuleName,

        [Parameter(Mandatory = $true)]
        [string]$DedicatedCachePath
    )

    Write-Log -Message "Required module '$ModuleName' was not found. Installing it automatically (use -InstallMissingModules:`$false to disable this)." -Level Info

    try {
        Initialize-NuGetProviderForCurrentUser
    }
    catch {
        Write-Log -Message "Could not pre-install the NuGet package provider: $(Get-FullErrorDetailText -ErrorRecord $_). Proceeding to attempt module installation directly." -Level Warning
    }

    # ATTEMPT 1: the standard, documented approach. Works in the majority of environments.
    try {
        Write-Log -Message "Attempting standard installation: Install-Module -Name $ModuleName -Scope CurrentUser" -Level Info
        Install-Module -Name $ModuleName -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop

        $installedModule = Get-FreshlyInstalledModuleInfo -ModuleName $ModuleName
        if ($null -ne $installedModule) {
            Write-Log -Message "Installed '$ModuleName' version '$($installedModule.Version)' via standard Install-Module." -Level Success
            return $installedModule
        }

        Write-Log -Message "Install-Module reported success for '$ModuleName' but it could not be located afterward. Falling back to the dedicated-folder method below." -Level Warning
    }
    catch {
        Write-Log -Message "Standard installation of '$ModuleName' failed. $(Get-FullErrorDetailText -ErrorRecord $_)" -Level Warning
        if ($_.Exception.Message -match '(?i)Administrator rights are required') {
            Write-Log -Message 'This specific error can occur even with -Scope CurrentUser and even for genuine administrators, when the Documents-based CurrentUser module path is blocked (for example, by OneDrive folder redirection or Windows Defender Controlled Folder Access). Falling back to installing into a dedicated, non-Documents folder instead of guessing further.' -Level Warning
        }
    }

    # ATTEMPT 2: Save-Module into a dedicated folder outside Documents, added to PSModulePath for this
    # process. Save-Module only downloads and copies files; it does not go through Install-Module's
    # AllUsers/CurrentUser scope-resolution logic at all, so it sidesteps failures caused by that scope
    # resolution specifically (for example, the Documents/OneDrive path problem it was originally added
    # for). NOTE: Save-Module and Install-Module both sit on top of the SAME underlying PackageManagement/
    # NuGet-provider download engine, so they do NOT sidestep failures that originate in that shared engine
    # itself, such as FullyQualifiedErrorId 'ProviderFailToDownloadFile' - that specific error is a
    # documented flaw in the legacy download path (confirmed in PowerShellGetv2 GitHub issue #667 and
    # PowerShellGallery issue #84: corrupted/interrupted package streams during download). Retrying that
    # same broken download path again would not be expected to reliably help, so that specific error is
    # detected below and routed directly to ATTEMPT 3 instead of being retried here.
    Write-Log -Message "Attempting fallback installation into dedicated folder: $DedicatedCachePath" -Level Info

    if (-not (Test-PathIsWritable -Path $DedicatedCachePath)) {
        throw "Neither the standard CurrentUser module location nor the dedicated fallback folder ('$DedicatedCachePath') are writable by this process. Diagnostics were logged above. Manual installation is required: pick a folder you know is writable, run Save-Module -Name $ModuleName -Path <that folder> -Repository PSGallery, then add <that folder> to `$env:PSModulePath and re-run this script."
    }

    # Distinguishes "PSGallery itself is unreachable/untrusted/unregistered" (affects every module the same
    # way) from a problem specific to this one module or this one destination folder, before blaming the
    # destination folder for what might actually be a repository-level problem.
    $galleryOk = Test-PSGalleryReachableAndTrusted

    # Always start ATTEMPT 2 from a clean slate: remove any existing (possibly incomplete/corrupted, from a
    # previous failed run) copy of this module from the dedicated cache before the first Save-Module call,
    # rather than only reacting to a failure after the fact.
    $null = Remove-ExistingModuleCacheEntry -ModuleName $ModuleName -DedicatedCachePath $DedicatedCachePath -Reason 'the dedicated-folder Save-Module attempt'

    # Self-healing retry for the single most common recoverable cause of a plain "Unable to save the
    # module" (unrelated to ProviderFailToDownloadFile specifically): a left-over partial copy written
    # DURING this same attempt's own failed run, which can make a fresh Save-Module refuse to overwrite
    # cleanly even with -Force. This only ever removes this specific module's own subfolder, never anything
    # else in the dedicated cache.
    $moduleDestinationPath = Join-Path -Path $DedicatedCachePath -ChildPath $ModuleName
    $attemptedCleanRetry = $false
    $savedSuccessfully = $false
    $lastSaveModuleDetailText = $null

    for ($saveAttempt = 1; $saveAttempt -le 2; $saveAttempt++) {
        try {
            Save-Module -Name $ModuleName -Path $DedicatedCachePath -Repository PSGallery -Force -ErrorAction Stop
            $savedSuccessfully = $true
            break
        }
        catch {
            $detailText = Get-FullErrorDetailText -ErrorRecord $_
            $lastSaveModuleDetailText = $detailText

            if ($_.FullyQualifiedErrorId -match 'ProviderFailToDownloadFile') {
                Write-Log -Message "Save-Module failed for '$ModuleName' with the known PackageManagement download-engine defect (ProviderFailToDownloadFile - see PowerShellGetv2 GitHub issue #667). $detailText" -Level Warning
                Write-Log -Message 'Skipping further retries of this same download path and moving directly to the modern Install-PSResource/PSResourceGet fallback, which uses a different download implementation entirely.' -Level Info
                break
            }

            if ($saveAttempt -eq 1 -and (Test-Path -Path $moduleDestinationPath)) {
                Write-Log -Message "Save-Module attempt $saveAttempt failed for '$ModuleName'. $detailText" -Level Warning
                Write-Log -Message "A previous partial/incomplete copy exists at '$moduleDestinationPath'. Removing it and retrying once, in case that leftover state is the cause." -Level Info
                $attemptedCleanRetry = $true
                try {
                    Remove-Item -Path $moduleDestinationPath -Recurse -Force -ErrorAction Stop
                }
                catch {
                    Write-Log -Message "Could not remove '$moduleDestinationPath' to retry cleanly: $($_.Exception.Message)" -Level Warning
                }
                continue
            }

            # Any other, unrecognized Save-Module failure: still worth trying ATTEMPT 3 below rather than
            # giving up immediately, but without pretending to know the cause any more precisely than this.
            Write-Log -Message "Save-Module attempt $saveAttempt failed for '$ModuleName' with an unrecognized error. $detailText" -Level Warning
            break
        }
    }

    if ($savedSuccessfully) {
        if (($env:PSModulePath -split [System.IO.Path]::PathSeparator) -notcontains $DedicatedCachePath) {
            $env:PSModulePath = "$DedicatedCachePath$([System.IO.Path]::PathSeparator)$env:PSModulePath"
        }

        $savedModule = Get-Module -ListAvailable -Name $ModuleName | Sort-Object Version -Descending | Select-Object -First 1
        if ($null -ne $savedModule) {
            Write-Log -Message "Installed '$ModuleName' version '$($savedModule.Version)' via the dedicated-folder fallback ($DedicatedCachePath). Loading it now without needing to restart PowerShell." -Level Success
            return [pscustomobject]@{ Version = $savedModule.Version; ManifestPath = $savedModule.Path }
        }

        Write-Log -Message "Module '$ModuleName' was saved to '$DedicatedCachePath' but could not be located afterward, even after adding that folder to `$env:PSModulePath for this session. Trying the Install-PSResource fallback next." -Level Warning
    }

    # ATTEMPT 3: Install-PSResource / Save-PSResource from the Microsoft.PowerShell.PSResourceGet module.
    # This is the official, modern replacement for PowerShellGet v2 (built into PowerShell 7.4 and later by
    # default, which includes the 7.6.3 this script is running under), and it uses its own independent
    # download implementation rather than the legacy PackageManagement/NuGet-provider engine that both
    # Install-Module and Save-Module above rely on. This means it is not affected by
    # ProviderFailToDownloadFile at all, since that defect lives specifically in the legacy engine, not in
    # the module content or the destination folder.
    $psResourceGetModule = Get-Module -ListAvailable -Name Microsoft.PowerShell.PSResourceGet | Select-Object -First 1
    if ($null -eq $psResourceGetModule) {
        $repositoryGuidance = if (-not $galleryOk) {
            ' PSGallery itself also appeared unreachable or unusable in the check earlier - that may be the deeper root cause across all of these attempts.'
        }
        else {
            ''
        }
        throw "Installation of '$ModuleName' failed via both Install-Module and Save-Module (last Save-Module detail: $lastSaveModuleDetailText), and the Microsoft.PowerShell.PSResourceGet module (which would provide one more, independent download path) is not available on this system to attempt a third method.$repositoryGuidance Diagnostics were logged above."
    }

    Write-Log -Message "Attempting fallback installation via Install-PSResource (Microsoft.PowerShell.PSResourceGet), a different download implementation than the previous two attempts." -Level Info

    # Confirmed real-world evidence: ATTEMPT 2 (Save-Module) can fail partway through with
    # ProviderFailToDownloadFile after already writing SOME files for this module into the dedicated cache,
    # and this script previously broke out of that attempt without cleaning those partial files up. That
    # leftover, incomplete folder (observed missing its .format.ps1xml) then caused Install-PSResource /
    # Save-PSResource below to fail with an unrelated-looking CommandNotFoundException from Import-Module
    # trying to load that same broken folder. Cleaning up before this attempt starts removes that specific,
    # now-confirmed failure path entirely, rather than leaving it to reappear on some future run.
    $null = Remove-ExistingModuleCacheEntry -ModuleName $ModuleName -DedicatedCachePath $DedicatedCachePath -Reason 'the Install-PSResource/Save-PSResource attempt'

    for ($psResourceAttempt = 1; $psResourceAttempt -le 2; $psResourceAttempt++) {
        try {
            Import-Module -Name Microsoft.PowerShell.PSResourceGet -ErrorAction Stop

            try {
                Install-PSResource -Name $ModuleName -Scope CurrentUser -TrustRepository -Reinstall -ErrorAction Stop -WarningAction SilentlyContinue
            }
            catch {
                Write-Log -Message "Install-PSResource -Scope CurrentUser failed for '$ModuleName': $(Get-FullErrorDetailText -ErrorRecord $_). Trying Save-PSResource into the dedicated folder instead." -Level Warning
                Save-PSResource -Name $ModuleName -Path $DedicatedCachePath -TrustRepository -Reinstall -ErrorAction Stop -WarningAction SilentlyContinue

                if (($env:PSModulePath -split [System.IO.Path]::PathSeparator) -notcontains $DedicatedCachePath) {
                    $env:PSModulePath = "$DedicatedCachePath$([System.IO.Path]::PathSeparator)$env:PSModulePath"
                }
            }

            break
        }
        catch {
            $psResourceDetailText = Get-FullErrorDetailText -ErrorRecord $_

            # This exact signature (a genuine Import-Module CommandNotFoundException reporting a missing
            # file inside what should be a complete module folder) means corrupted/incomplete local content,
            # not a download-permission or network problem. One clean retry directly addresses that.
            $looksLikeCorruptedLocalCache = ($_.FullyQualifiedErrorId -match 'CommandNotFoundException.*ImportModuleCommand') -or ($_.Exception.Message -match "(?i)could not find file.*\.(format|types)\.ps1xml")

            if ($psResourceAttempt -eq 1 -and $looksLikeCorruptedLocalCache) {
                Write-Log -Message "Install-PSResource/Save-PSResource failed for '$ModuleName' due to what looks like corrupted/incomplete local module content (not a network or permissions problem). $psResourceDetailText" -Level Warning
                Write-Log -Message 'Cleaning the dedicated cache for this module and retrying once more.' -Level Info
                $null = Remove-ExistingModuleCacheEntry -ModuleName $ModuleName -DedicatedCachePath $DedicatedCachePath -Reason 'a clean retry of the Install-PSResource/Save-PSResource attempt'
                continue
            }

            throw "Installation of '$ModuleName' failed via Install-Module, Save-Module, and Install-PSResource/Save-PSResource (PSResourceGet attempt(s): $psResourceAttempt). This means all available module-download mechanisms on this machine failed for the same package; the most likely remaining cause is a network/proxy/firewall restriction blocking access to PowerShell Gallery (powershellgallery.com) specifically, rather than anything about this script or this module. PSResourceGet error detail: $psResourceDetailText. Diagnostics were logged above."
        }
    }

    $psResourceInstalledModule = Get-Module -ListAvailable -Name $ModuleName | Sort-Object Version -Descending | Select-Object -First 1
    if ($null -eq $psResourceInstalledModule) {
        throw "Install-PSResource/Save-PSResource reported success for '$ModuleName' but it could not be located afterward. Diagnostics were logged above."
    }

    Write-Log -Message "Installed '$ModuleName' version '$($psResourceInstalledModule.Version)' via Install-PSResource/PSResourceGet. Loading it now without needing to restart PowerShell." -Level Success
    return [pscustomobject]@{ Version = $psResourceInstalledModule.Version; ManifestPath = $psResourceInstalledModule.Path }
}

function Test-ControlledFolderAccessStatus {
    [CmdletBinding()]
    param()

    # Get-MpPreference is a read-only query against Windows Defender and does not require elevation.
    # Confirmed real-world cause for this environment: Controlled Folder Access blocks writes from
    # non-allow-listed processes (like powershell.exe/pwsh.exe running a module-installation script)
    # regardless of whether that process is running elevated/as Administrator - CFA operates independently
    # of UAC/admin rights entirely, which is exactly why "running as admin" did not help here.
    try {
        $preference = Get-MpPreference -ErrorAction Stop
        $property = $preference.PSObject.Properties['EnableControlledFolderAccess']
        if ($null -eq $property) {
            return $null
        }
        # Values: 0 = Disabled, 1 = Enabled, 2 = Audit Mode.
        return [int]$property.Value
    }
    catch {
        # Not Windows, Defender not present/active, or the cmdlet is otherwise unavailable. Not an error
        # condition for this script - just means this specific diagnostic cannot be reported.
        return $null
    }
}

function Get-ModuleVersionFolderPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ManifestPath
    )

    # A module manifest normally lives at <ModuleRoot>\<ModuleName>\<Version>\<ModuleName>.psd1, so two
    # levels up from the manifest file is the version folder - the safe, correct unit to delete and
    # reinstall when that specific version is found to be corrupted, without touching sibling versions.
    try {
        return Split-Path -Path $ManifestPath -Parent
    }
    catch {
        return $null
    }
}

function Test-PathIsUnderDedicatedCache {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$DedicatedCachePath
    )

    # SAFETY GUARD: automatic deletion of a corrupted module folder must never be allowed to touch a
    # system-wide or PowerShell-Gallery-managed module location (for example, Program Files, the system
    # PowerShell module path, or another application's modules). This script only ever created and owns
    # files under its own dedicated cache folder, so cleanup is strictly limited to paths physically inside
    # that folder.
    if ([string]::IsNullOrWhiteSpace($Path)) {
        return $false
    }

    try {
        $fullPath = [System.IO.Path]::GetFullPath($Path)
        $fullCachePath = [System.IO.Path]::GetFullPath($DedicatedCachePath)
        return $fullPath.StartsWith($fullCachePath, [StringComparison]::OrdinalIgnoreCase)
    }
    catch {
        return $false
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

    $dedicatedCachePath = Get-DedicatedModuleCachePath

    # If a previous run already fell back to the dedicated cache folder, make sure it is on PSModulePath
    # from the very start of this run too, so previously-installed modules are found immediately without
    # attempting (and re-failing) the standard installation path all over again.
    if ((Test-Path -Path $dedicatedCachePath) -and (($env:PSModulePath -split [System.IO.Path]::PathSeparator) -notcontains $dedicatedCachePath)) {
        $env:PSModulePath = "$dedicatedCachePath$([System.IO.Path]::PathSeparator)$env:PSModulePath"
    }

    $diagnosticsLogged = $false

    foreach ($moduleName in $requiredModules) {
        # Allows exactly one self-heal cycle: if the first import attempt fails because this module's own
        # on-disk files are corrupted/incomplete (the confirmed Controlled Folder Access signature - a
        # module folder that Get-Module -ListAvailable finds via its .psd1, but where CFA silently blocked
        # one or more of the other files inside that same folder during installation), the corrupted
        # version folder is removed and a fresh install + import is attempted once more automatically.
        for ($healAttempt = 1; $healAttempt -le 2; $healAttempt++) {
            $alreadyImportedModule = Get-Module -Name $moduleName | Select-Object -First 1
            $moduleToImport = $null

            $availableModule = Get-Module -ListAvailable -Name $moduleName | Sort-Object Version -Descending | Select-Object -First 1

            if ($null -eq $availableModule) {
                if (-not $InstallIfMissing) {
                    # Only reachable if the caller explicitly opted out with -InstallMissingModules:$false;
                    # module installation happens automatically by default so you never have to know in
                    # advance whether a required module is already present.
                    throw "Required module '$moduleName' is not installed, and automatic installation was disabled with -InstallMissingModules:`$false. Install it manually with: Install-Module $moduleName -Scope CurrentUser"
                }

                if (-not $diagnosticsLogged) {
                    # Only needs to happen once per script run, not once per module.
                    Write-ModuleInstallDiagnostics
                    $diagnosticsLogged = $true
                }

                $moduleToImport = Install-RequiredGraphModule -ModuleName $moduleName -DedicatedCachePath $dedicatedCachePath
            }
            else {
                $moduleToImport = [pscustomobject]@{ Version = $availableModule.Version; ManifestPath = $availableModule.Path }
            }

            try {
                if ($null -ne $alreadyImportedModule -and $alreadyImportedModule.Version -ne $moduleToImport.Version) {
                    # A different version of this module is already loaded in the current session (for
                    # example, from an earlier command, a PowerShell profile, or a prior
                    # -InstallMissingModules run this same session). Remove it first so the correct version
                    # can be loaded cleanly.
                    Write-Log -Message "Version $($alreadyImportedModule.Version) of '$moduleName' is already loaded in this session. Removing it before loading version $($moduleToImport.Version)." -Level Info
                    Remove-Module -Name $moduleName -Force -ErrorAction Stop
                }

                if (-not [string]::IsNullOrWhiteSpace([string]$moduleToImport.ManifestPath)) {
                    Import-Module -Name $moduleToImport.ManifestPath -Force -Global -ErrorAction Stop
                }
                else {
                    Import-Module -Name $moduleName -Force -Global -ErrorAction Stop
                }

                $finalModule = Get-Module -Name $moduleName | Select-Object -First 1
                Write-Log -Message "Loaded module '$moduleName' version '$($finalModule.Version)'." -Level Debug
                break
            }
            catch {
                $isMissingFileError = ($_.Exception -is [System.IO.FileNotFoundException]) -or ($_.Exception.InnerException -is [System.IO.FileNotFoundException]) -or ($_.Exception.Message -match "(?i)Could not find (the specified module|file)")
                $corruptedVersionFolder = if ($isMissingFileError) { Get-ModuleVersionFolderPath -ManifestPath $moduleToImport.ManifestPath } else { $null }
                $canSelfHeal = $isMissingFileError -and (Test-PathIsUnderDedicatedCache -Path $corruptedVersionFolder -DedicatedCachePath $dedicatedCachePath) -and ($healAttempt -eq 1)

                if ($canSelfHeal) {
                    # This is the confirmed corruption signature: a module that Get-Module -ListAvailable
                    # reports as present (its .psd1 manifest exists) but that fails to actually load because
                    # one or more of its other files is missing on disk - exactly what happens when
                    # Controlled Folder Access silently blocks a file write mid-installation. Safe to
                    # auto-remove because Test-PathIsUnderDedicatedCache confirmed this folder belongs
                    # exclusively to this script's own dedicated cache, never a system-wide module location.
                    Write-Log -Message "Detected a corrupted/incomplete installation of '$moduleName' at '$corruptedVersionFolder' (a file inside this module's folder could not be found, even though the module itself was detected as present). This matches the signature of Windows Defender Controlled Folder Access silently blocking a file write during installation, independently of admin rights." -Level Warning
                    Write-Log -Message "Removing the corrupted folder and attempting a fresh install of '$moduleName' automatically." -Level Info

                    try {
                        Remove-Item -Path $corruptedVersionFolder -Recurse -Force -ErrorAction Stop
                        Remove-Module -Name $moduleName -Force -ErrorAction SilentlyContinue
                    }
                    catch {
                        Write-Log -Message "Could not remove the corrupted folder '$corruptedVersionFolder': $($_.Exception.Message). Self-heal cannot proceed; see the Controlled Folder Access guidance below." -Level Warning
                    }

                    continue
                }

                $cfaStatus = Test-ControlledFolderAccessStatus
                $cfaGuidance = if ($isMissingFileError -and $cfaStatus -eq 1) {
                    $currentHostExecutableName = if ($PSVersionTable.PSEdition -eq 'Core') { 'pwsh.exe' } else { 'powershell.exe' }
                    $currentHostExecutablePath = Join-Path -Path $PSHOME -ChildPath $currentHostExecutableName
                    " This matches the confirmed Windows Defender Controlled Folder Access signature (CFA is ENABLED on this machine and blocks writes independently of admin rights). Remediation: open Windows Security > Virus & threat protection > Manage ransomware protection > Controlled folder access > Allow an app through Controlled folder access, and add $currentHostExecutableName (full path: $currentHostExecutablePath). Alternatively, temporarily turn Controlled folder access Off, run this script once to install the modules, then turn it back on. If this machine is managed by your organization, your security/Intune administrator may need to add this exclusion instead."
                }
                elseif ($isMissingFileError) {
                    ' This looks like a corrupted/incomplete module installation, but it could not be safely auto-repaired (either a second occurrence, or the affected folder is outside this script''s own dedicated cache). Manually delete the affected module folder shown above and re-run this script.'
                }
                else {
                    # GENUINE REMAINING LIMITATION: if a conflicting version of this module's underlying
                    # .NET assemblies was already loaded into this process by an earlier command in this
                    # same session (or by a PowerShell profile script) before this script ran, the CLR
                    # cannot swap out an already-loaded assembly for a different version without starting a
                    # new process. This applies to both Windows PowerShell 5.1 and PowerShell 7+ (Core).
                    # This is the one scenario that can still legitimately require closing and reopening
                    # PowerShell, but it is now reported clearly and only happens in that specific
                    # pre-existing-conflict case, rather than on every routine first-time install.
                    ' If a different version of this module was already loaded earlier in this PowerShell session (or by your PowerShell profile), open a new PowerShell window and re-run the script; this can be a .NET assembly-loading limitation rather than a problem with the installation itself.'
                }

                throw "Failed to load '$moduleName' after installation: $($_.Exception.Message).$cfaGuidance"
            }
        }
    }
}

function Test-IsElevatedProcess {
    [CmdletBinding()]
    param()

    try {
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        # Not running on Windows, or unable to determine elevation for some other reason. Returning $false
        # here just means the elevation-specific warning below is skipped; it does not affect functionality.
        return $false
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

            # KNOWN SDK LIMITATION (Microsoft.Graph.Authentication 2.34.0+, confirmed against your installed
            # 2.36.1): interactive sign-in now forces Windows Web Account Manager (WAM) as the broker on
            # Windows, and this cannot be turned off via Set-MgGraphOption -EnableLoginByWAM $false on this
            # version (that setting only has an effect on versions below 2.34.0). Two WAM failure patterns
            # produce exactly "the auth window never comes up," with no error and no visible prompt:
            #   1. PowerShell is running elevated ("Run as Administrator") or under a different user context.
            #      WAM requires the broker to match the interactive desktop session of the signed-in Windows
            #      user; when it does not match, the process can hang indefinitely with zero visible window
            #      (see microsoftgraph/msgraph-sdk-powershell issues #3538 and #3489).
            #   2. PowerShell is running inside an embedded terminal (VS Code integrated terminal, ISE, some
            #      IDEs). The window can still open but get hidden behind other windows instead of coming to
            #      the foreground.
            # This is a genuine SDK/OS broker limitation, not something this script's code can work around,
            # so the guidance below is surfaced proactively before the hang would otherwise occur.
            if (Test-IsElevatedProcess) {
                Write-Log -Message 'This PowerShell session is running elevated (as Administrator). Interactive sign-in can silently hang forever in this configuration due to a known Microsoft Graph SDK/WAM broker limitation.' -Level Action
                Write-Host 'Recommended: close this window and re-run the script from a standard (non-elevated) PowerShell console signed in as the account you intend to authenticate with.'
                Write-Host 'Alternatively, choose -AuthenticationMethod DeviceCode (most reliable regardless of elevation) or -AuthenticationMethod Certificate for unattended/app-only scenarios.'
            }
            else {
                Write-Log -Message 'If no sign-in window appears within a few seconds, check your taskbar and other open windows; it can render behind them instead of coming to the foreground. If nothing appears at all, this is likely running inside an embedded terminal or IDE - try a standard PowerShell console, or use -AuthenticationMethod DeviceCode instead.' -Level Info
            }

            try {
                # Best-effort only. This has no effect on Microsoft.Graph.Authentication 2.34.0+ (WAM is
                # mandatory there and this call is silently ignored), but it is harmless to attempt and
                # restores the classic non-WAM browser flow automatically on older installed SDK versions.
                Set-MgGraphOption -EnableLoginByWAM $false -ErrorAction Stop
            }
            catch {
                # Cmdlet/parameter not present, or the setting was ignored by the installed SDK version.
                # Nothing to act on; this is expected on 2.34.0 and later.
            }
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
    elseif ($null -eq (Get-Module -Name Microsoft.Graph.Authentication)) {
        # Get-MgContext/Disconnect-MgGraph do not exist as commands until Microsoft.Graph.Authentication has
        # actually been imported into this session. If the script failed before that point (for example, the
        # module was not installed and -InstallMissingModules was not specified), calling them here would
        # throw its own "term ... is not recognized" error - which is misleading noise on top of the real,
        # already-reported cause, and is exactly what happened when this module was missing. There is
        # nothing to disconnect in this case, so it is silently skipped rather than logged, since it is
        # normal and expected whenever the script fails before authentication was ever attempted.
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
