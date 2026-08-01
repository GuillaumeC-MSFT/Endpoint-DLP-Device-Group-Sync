<#
================================================================================
Sync-UserGroupDevicesToDeviceGroup_v3.ps1
================================================================================

 PURPOSE
    This script supports Endpoint DLP testing and rollout scenarios where a user
    security group must be matched to the devices associated with those users,
    then those devices must be placed in a Microsoft Entra device security group.

    The script:
      - Presents an interactive menu when no mode is provided.
      - Uses device-code authentication by default to avoid hidden WAM/browser prompts.
      - Checks whether required Microsoft Graph PowerShell modules are present.
      - Offers to install Microsoft.Graph if required modules are missing.
      - Prompts for the source user group and destination device group.
      - Checks whether the destination device group exists before processing users.
      - Prompts to create the destination device security group if it does not exist.
      - Waits for newly created groups to become queryable before continuing.
      - Loops through each direct user member in the source group.
      - Looks up devices registered to each user through Microsoft Graph.
      - Adds matched device objects to the destination device group in Apply mode.
      - Produces a main CSV report, users-without-devices CSV report, and log file.

 IMPORTANT ENDPOINT DLP NOTE
    This script is user-first. It starts with users and asks Microsoft Graph which
    devices are associated with each user. Kiosk/shared/userless devices are not
    expected to be matched because there is no user-to-device relationship to use.

    Users in the source group with no associated device are highlighted clearly
    because that is a potential Endpoint DLP coverage issue when policy scoping
    depends on both user and device group matching.

 DISCLAIMER
    This script is provided as a sample and starting point only. It should be
    reviewed, validated, and tested in a non-production environment before using
    it in production.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.

 PREREQUISITES
    - PowerShell 5.1+ or PowerShell 7+
    - Microsoft Graph PowerShell SDK. If missing, this script can prompt to run:
          Install-Module Microsoft.Graph -Scope CurrentUser -Repository PSGallery -Force -AllowClobber
    - Delegated Graph permissions requested by the script:
          User.Read.All
          Device.Read.All
          Group.Read.All
          Group.ReadWrite.All
          GroupMember.Read.All
          GroupMember.ReadWrite.All

 EXAMPLES
    .\Sync-UserGroupDevicesToDeviceGroup.ps1

    .\Sync-UserGroupDevicesToDeviceGroup.ps1 -Mode ReportOnly -SourceUserGroupName "Risky Users" -DestinationDeviceGroupName "Risky Users - Endpoint DLP Devices"

    .\Sync-UserGroupDevicesToDeviceGroup.ps1 -Mode Apply -SourceUserGroupName "Risky Users" -DestinationDeviceGroupName "Risky Users - Endpoint DLP Devices"

================================================================================
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$SourceUserGroupName,

    [Parameter()]
    [string]$DestinationDeviceGroupName,

    [Parameter()]
    [ValidateSet("ReportOnly", "CreateGroupOnly", "Apply")]
    [string]$Mode,

    [Parameter()]
    [switch]$UseInteractiveBrowser,

    [Parameter()]
    [switch]$CorporateOnly,

    [Parameter()]
    [switch]$PersonalOnly,

    [Parameter()]
    [ValidateRange(1, 30)]
    [int]$MembershipMaxRetries = 8,

    [Parameter()]
    [ValidateRange(1, 120)]
    [int]$MembershipRetryBaseDelaySeconds = 10,

    [Parameter()]
    [ValidateRange(30, 900)]
    [int]$GroupAvailabilityTimeoutSeconds = 180,

    [Parameter()]
    [string]$OutputPath = (Get-Location).Path
)

$ErrorActionPreference = "Stop"
$scriptStart = Get-Date
$timestamp = $scriptStart.ToString("yyyyMMdd_HHmmss")

if (-not (Test-Path $OutputPath)) {
    Write-Host "OutputPath '$OutputPath' does not exist. Create it first or provide a valid folder." -ForegroundColor Red
    return
}

$logFile = Join-Path $OutputPath "EDLP_DeviceGroupSync_$timestamp.log"
$mainCsvFile = Join-Path $OutputPath "EDLP_DeviceGroupSync_MainReport_$timestamp.csv"
$exceptionsCsvFile = Join-Path $OutputPath "EDLP_DeviceGroupSync_UsersWithoutDevices_$timestamp.csv"

function Write-Log {
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [Parameter()][ValidateSet("INFO", "WARN", "ERROR", "SUCCESS", "IMPORTANT")][string]$Level = "INFO"
    )

    $line = "[{0}] [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Level, $Message

    switch ($Level) {
        "ERROR"     { Write-Host $line -ForegroundColor Red }
        "WARN"      { Write-Host $line -ForegroundColor Yellow }
        "SUCCESS"   { Write-Host $line -ForegroundColor Green }
        "IMPORTANT" { Write-Host $line -ForegroundColor Magenta }
        default      { Write-Host $line }
    }

    Add-Content -Path $logFile -Value $line
}

function Read-YesNo {
    param(
        [Parameter(Mandatory = $true)][string]$Prompt,
        [Parameter()][bool]$DefaultNo = $true
    )

    $suffix = if ($DefaultNo) { "(Y/N, default N)" } else { "(Y/N, default Y)" }
    $answer = Read-Host "$Prompt $suffix"

    if ([string]::IsNullOrWhiteSpace($answer)) {
        return (-not $DefaultNo)
    }

    return ($answer -match "^(?i)(y|yes)$")
}

function Show-Menu {
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host " Endpoint DLP User-to-Device Group Helper" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "1. Report only - no membership changes"
    Write-Host "2. Create/check destination device group only"
    Write-Host "3. Apply - create/check group and add matched devices"
    Write-Host "4. Exit"
    Write-Host ""

    do { $choice = Read-Host "Select an option [1-4]" } until ($choice -in @("1", "2", "3", "4"))

    switch ($choice) {
        "1" { return "ReportOnly" }
        "2" { return "CreateGroupOnly" }
        "3" { return "Apply" }
        "4" { return "Exit" }
    }
}

function Escape-ODataString {
    param([Parameter(Mandatory = $true)][string]$Value)
    return $Value.Replace("'", "''")
}

function New-SafeMailNickname {
    param([Parameter(Mandatory = $true)][string]$DisplayName)
    $nickname = ($DisplayName -replace '[^A-Za-z0-9\-_]', '')
    if ([string]::IsNullOrWhiteSpace($nickname)) { $nickname = "DeviceGroup" }
    if ($nickname.Length -gt 64) { $nickname = $nickname.Substring(0, 64) }
    return $nickname
}

function Ensure-GraphModules {
    $requiredModules = @(
        "Microsoft.Graph.Authentication",
        "Microsoft.Graph.Groups",
        "Microsoft.Graph.Users"
    )

    $missingModules = @()
    foreach ($moduleName in $requiredModules) {
        if (-not (Get-Module -ListAvailable -Name $moduleName)) {
            $missingModules += $moduleName
        }
    }

    if ($missingModules.Count -gt 0) {
        Write-Log "Missing Microsoft Graph module(s): $($missingModules -join ', ')" "WARN"
        Write-Host ""
        Write-Host "The Microsoft Graph PowerShell SDK, or one of its required sub-modules, is missing." -ForegroundColor Yellow
        Write-Host "Recommended install command:" -ForegroundColor Yellow
        Write-Host "Install-Module Microsoft.Graph -Scope CurrentUser -Repository PSGallery -Force -AllowClobber" -ForegroundColor Cyan
        Write-Host ""

        if (Read-YesNo -Prompt "Do you want the script to attempt the installation now?" -DefaultNo $true) {
            try {
                Write-Log "Installing Microsoft.Graph from PSGallery for current user." "IMPORTANT"
                Install-Module Microsoft.Graph -Scope CurrentUser -Repository PSGallery -Force -AllowClobber -ErrorAction Stop
                Write-Log "Microsoft.Graph install command completed." "SUCCESS"
            }
            catch {
                throw "Module installation failed. Run this manually, then retry: Install-Module Microsoft.Graph -Scope CurrentUser -Repository PSGallery -Force -AllowClobber. Error: $($_.Exception.Message)"
            }
        }
        else {
            throw "Required Microsoft Graph modules are missing. Install Microsoft.Graph and re-run the script."
        }
    }

    foreach ($moduleName in $requiredModules) {
        Import-Module $moduleName -ErrorAction Stop
    }

    $requiredCommands = @(
        "Connect-MgGraph",
        "Disconnect-MgGraph",
        "Get-MgContext",
        "Get-MgGroup",
        "New-MgGroup",
        "Get-MgGroupMember",
        "New-MgGroupMemberByRef",
        "Get-MgUser",
        "Get-MgUserRegisteredDevice"
    )

    $missingCommands = @()
    foreach ($commandName in $requiredCommands) {
        if (-not (Get-Command $commandName -ErrorAction SilentlyContinue)) {
            $missingCommands += $commandName
        }
    }

    if ($missingCommands.Count -gt 0) {
        throw "Required Microsoft Graph command(s) not available after module import: $($missingCommands -join ', '). Try updating Microsoft.Graph."
    }

    Write-Log "Required Microsoft Graph modules and commands are available." "SUCCESS"
}

function Get-ConnectMgGraphDeviceCodeParameterName {
    $connectCommand = Get-Command Connect-MgGraph -ErrorAction Stop
    if ($connectCommand.Parameters.ContainsKey("UseDeviceCode")) { return "UseDeviceCode" }
    if ($connectCommand.Parameters.ContainsKey("UseDeviceAuthentication")) { return "UseDeviceAuthentication" }
    throw "This version of Connect-MgGraph does not expose a device-code authentication parameter. Update Microsoft.Graph."
}

function Show-AuthenticationMenu {
    Write-Host ""
    Write-Host "Authentication options" -ForegroundColor Cyan
    Write-Host "1. Device code authentication (recommended for terminals / avoids hidden browser windows)"
    Write-Host "2. Interactive browser authentication"
    Write-Host "3. App-only authentication with Client ID + Tenant ID + Certificate Thumbprint"
    Write-Host "4. Exit"
    Write-Host ""

    do { $choice = Read-Host "Select an authentication option [1-4]" } until ($choice -in @("1", "2", "3", "4"))
    return $choice
}

function Get-ConnectMgGraphDeviceCodeParameterName {
    $connectCommand = Get-Command Connect-MgGraph -ErrorAction Stop
    if ($connectCommand.Parameters.ContainsKey("UseDeviceCode")) { return "UseDeviceCode" }
    if ($connectCommand.Parameters.ContainsKey("UseDeviceAuthentication")) { return "UseDeviceAuthentication" }
    return $null
}

function Test-GraphConnection {
    try {
        $context = Get-MgContext
        if (-not $context) { throw "No active Microsoft Graph context was created." }
        Write-Log "Connected to tenant ID: $($context.TenantId)" "SUCCESS"
        $null = Get-MgGroup -Top 1 -ErrorAction Stop
        Write-Log "Microsoft Graph connectivity validated with a test group query." "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Graph connection validation failed: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Connect-GraphSession {
    param([Parameter(Mandatory = $true)][string[]]$Scopes)

    $baseParams = @{
        Scopes      = $Scopes
        NoWelcome   = $true
        ErrorAction = "Stop"
    }

    $connectCommand = Get-Command Connect-MgGraph -ErrorAction Stop
    if ($connectCommand.Parameters.ContainsKey("ContextScope")) {
        $baseParams["ContextScope"] = "Process"
    }

    while ($true) {
        # If -UseInteractiveBrowser was provided, try browser first once. Otherwise, show the menu.
        if ($UseInteractiveBrowser) {
            $choice = "2"
            $UseInteractiveBrowser = $false
        }
        else {
            $choice = Show-AuthenticationMenu
        }

        if ($choice -eq "4") {
            throw "Authentication was cancelled by the operator."
        }

        try {
            switch ($choice) {
                "1" {
                    $deviceParamName = Get-ConnectMgGraphDeviceCodeParameterName
                    if (-not $deviceParamName) {
                        Write-Log "This Microsoft Graph PowerShell version does not expose a device-code authentication parameter. Try interactive browser authentication or update Microsoft.Graph." "WARN"
                        continue
                    }

                    $params = $baseParams.Clone()
                    $params[$deviceParamName] = $true
                    Write-Host ""
                    Write-Host "[ACTION REQUIRED] Device code sign-in selected." -ForegroundColor Cyan
                    Write-Host "Follow the device-code instructions shown below. If your tenant blocks device-code sign-in, return here and choose interactive browser or app-only authentication."
                    Write-Log "Attempting Microsoft Graph device-code authentication." "IMPORTANT"
                    Connect-MgGraph @params | Out-Host
                }
                "2" {
                    Write-Host ""
                    Write-Host "[INFO] Interactive browser sign-in selected." -ForegroundColor Cyan
                    Write-Host "If the browser or WAM prompt is hidden or hangs, cancel and choose device code or app-only authentication."
                    Write-Log "Attempting Microsoft Graph interactive browser authentication." "IMPORTANT"
                    Connect-MgGraph @baseParams
                }
                "3" {
                    Write-Host ""
                    Write-Host "[ACTION REQUIRED] App-only authentication selected." -ForegroundColor Cyan
                    Write-Host "You need an Entra app registration with the required Microsoft Graph application permissions already consented, plus a certificate available on this machine."
                    $clientId = Read-Host "Enter Application (client) ID"
                    $tenantId = Read-Host "Enter Tenant ID"
                    $thumbprint = Read-Host "Enter certificate thumbprint"

                    if ([string]::IsNullOrWhiteSpace($clientId) -or [string]::IsNullOrWhiteSpace($tenantId) -or [string]::IsNullOrWhiteSpace($thumbprint)) {
                        Write-Log "App-only authentication requires Client ID, Tenant ID, and certificate thumbprint. Returning to authentication menu." "WARN"
                        continue
                    }

                    $appParams = @{
                        ClientId              = $clientId
                        TenantId              = $tenantId
                        CertificateThumbprint = $thumbprint
                        NoWelcome             = $true
                        ErrorAction           = "Stop"
                    }
                    if ($connectCommand.Parameters.ContainsKey("ContextScope")) {
                        $appParams["ContextScope"] = "Process"
                    }
                    Write-Log "Attempting Microsoft Graph app-only certificate authentication." "IMPORTANT"
                    Connect-MgGraph @appParams
                }
            }

            if (Test-GraphConnection) {
                return
            }

            Write-Host ""
            Write-Host "[ACTION REQUIRED] Authentication completed but Graph validation failed." -ForegroundColor Cyan
            Write-Host "You can retry with another authentication method."
        }
        catch {
            Write-Log "Authentication attempt failed: $($_.Exception.Message)" "ERROR"
            Write-Host ""
            Write-Host "[ACTION REQUIRED] Authentication failed." -ForegroundColor Cyan
            Write-Host "Options: retry device code, try interactive browser, use app-only certificate authentication, or exit."
        }
    }
}

function Test-TransientGraphError {
    param([Parameter(Mandatory = $true)][string]$Message)

    $patterns = @(
        "429",
        "TooManyRequests",
        "temporarily unavailable",
        "ServiceUnavailable",
        "timeout",
        "timed out",
        "503",
        "504",
        "500",
        "source resource object or one of the objects being referenced don't exist",
        "one of the objects being referenced don't exist",
        "does not exist or one of its queried reference-property objects are not present",
        "Resource .* does not exist"
    )

    foreach ($pattern in $patterns) {
        if ($Message -match $pattern) { return $true }
    }
    return $false
}

function Invoke-GraphWithRetry {
    param(
        [Parameter(Mandatory = $true)][scriptblock]$Operation,
        [Parameter(Mandatory = $true)][string]$OperationName,
        [Parameter()][int]$MaxRetries = 5,
        [Parameter()][int]$BaseDelaySeconds = 5
    )

    for ($attempt = 1; $attempt -le $MaxRetries; $attempt++) {
        try { return & $Operation }
        catch {
            $message = $_.Exception.Message
            $isTransient = Test-TransientGraphError -Message $message
            if (($attempt -lt $MaxRetries) -and $isTransient) {
                $delay = [Math]::Min(($BaseDelaySeconds * $attempt), 90)
                Write-Log "$OperationName failed on attempt $attempt of $MaxRetries. Retrying in $delay seconds. Error: $message" "WARN"
                Start-Sleep -Seconds $delay
                continue
            }
            throw
        }
    }
}

function Get-SingleGroupByDisplayName {
    param([Parameter(Mandatory = $true)][string]$DisplayName)
    $escapedName = Escape-ODataString -Value $DisplayName
    $groups = @(Get-MgGroup -Filter "displayName eq '$escapedName'" -ConsistencyLevel eventual -ErrorAction Stop)
    if ($groups.Count -eq 0) { return $null }
    if ($groups.Count -gt 1) { throw "More than one group matches '$DisplayName'. Use a unique display name." }
    return $groups[0]
}

function Wait-GroupAvailable {
    param(
        [Parameter(Mandatory = $true)][string]$GroupId,
        [Parameter()][int]$TimeoutSeconds = 180,
        [Parameter()][int]$IntervalSeconds = 10
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $attempt = 0
    while ((Get-Date) -lt $deadline) {
        $attempt++
        try {
            $group = Get-MgGroup -GroupId $GroupId -ErrorAction Stop
            Write-Log "Destination group is queryable in Microsoft Graph. Attempt: $attempt." "SUCCESS"
            return $group
        }
        catch {
            Write-Log "Destination group is not queryable yet. Waiting $IntervalSeconds seconds. Attempt: $attempt." "WARN"
            Start-Sleep -Seconds $IntervalSeconds
        }
    }
    throw "Destination group '$GroupId' did not become queryable within $TimeoutSeconds seconds. Wait a few minutes and re-run."
}

function Get-GraphObjectProperty {
    param(
        [Parameter(Mandatory = $true)]$Object,
        [Parameter(Mandatory = $true)][string]$Name
    )
    if ($null -ne $Object.PSObject.Properties[$Name] -and $null -ne $Object.$Name) { return $Object.$Name }
    if ($Object.AdditionalProperties -and $Object.AdditionalProperties.ContainsKey($Name)) { return $Object.AdditionalProperties[$Name] }
    return $null
}

function New-ReportRow {
    param(
        [string]$UserPrincipalName,
        [string]$UserDisplayName,
        [string]$UserId,
        [string]$DeviceDisplayName,
        [string]$DeviceObjectId,
        [string]$OperatingSystem,
        [string]$Ownership,
        [string]$DestinationGroupName,
        [string]$AlreadyInDestinationGroup,
        [string]$PlannedAction,
        [string]$Result,
        [string]$CoverageConcern,
        [string]$Notes
    )

    [PSCustomObject]@{
        UserPrincipalName         = $UserPrincipalName
        UserDisplayName           = $UserDisplayName
        UserId                    = $UserId
        DeviceDisplayName         = $DeviceDisplayName
        DeviceObjectId            = $DeviceObjectId
        OperatingSystem           = $OperatingSystem
        Ownership                 = $Ownership
        DestinationGroupName      = $DestinationGroupName
        AlreadyInDestinationGroup = $AlreadyInDestinationGroup
        PlannedAction             = $PlannedAction
        Result                    = $Result
        CoverageConcern           = $CoverageConcern
        Notes                     = $Notes
    }
}

try {
    if ($CorporateOnly -and $PersonalOnly) {
        Write-Host "You cannot use -CorporateOnly and -PersonalOnly together." -ForegroundColor Red
        return
    }

    if ([string]::IsNullOrWhiteSpace($Mode)) {
        $Mode = Show-Menu
        if ($Mode -eq "Exit") { return }
    }

    if ([string]::IsNullOrWhiteSpace($SourceUserGroupName)) {
        $SourceUserGroupName = Read-Host "Enter the source USER security group display name"
    }

    if ([string]::IsNullOrWhiteSpace($DestinationDeviceGroupName)) {
        $DestinationDeviceGroupName = Read-Host "Enter the destination DEVICE security group display name"
    }

    Write-Host ""
    Write-Host "Run summary" -ForegroundColor Cyan
    Write-Host "Mode:                      $Mode"
    Write-Host "Authentication:            $(if ($UseInteractiveBrowser) { 'Interactive browser' } else { 'Device code' })"
    Write-Host "Source user group:         $SourceUserGroupName"
    Write-Host "Destination device group:  $DestinationDeviceGroupName"
    Write-Host "Output path:               $OutputPath"
    Write-Host ""

    if (-not (Read-YesNo -Prompt "Continue?" -DefaultNo $true)) { return }

    Write-Log "=== Script started ===" "IMPORTANT"
    Write-Log "Mode: $Mode" "IMPORTANT"
    Write-Log "Source user group: $SourceUserGroupName"
    Write-Log "Destination device group: $DestinationDeviceGroupName"

    Ensure-GraphModules

    $requiredScopes = @(
        "User.Read.All",
        "Device.Read.All",
        "Group.Read.All",
        "Group.ReadWrite.All",
        "GroupMember.Read.All",
        "GroupMember.ReadWrite.All"
    )

    Connect-GraphSession -Scopes $requiredScopes

    Write-Log "Checking source user group exists."

    while ($true) {
        $sourceGroup = Get-SingleGroupByDisplayName -DisplayName $SourceUserGroupName

        if (-not $sourceGroup) {
            Write-Host "" 
            Write-Host "[ACTION REQUIRED] SOURCE USER GROUP NOT FOUND" -ForegroundColor Cyan
            Write-Host "Group name: $SourceUserGroupName"
            Write-Host "Create the group, add one or more users, allow Entra ID replication, then return here."
            Write-Host "Press any key when ready to re-check..."
            $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
            $SourceUserGroupName = Read-Host "Enter the source user group name to validate"
            continue
        }

        $sourceMembers = @(Get-MgGroupMember -GroupId $sourceGroup.Id -All -ErrorAction Stop)
        $userMembersValidation = @($sourceMembers | Where-Object { $_.AdditionalProperties["@odata.type"] -eq "#microsoft.graph.user" })

        if ($userMembersValidation.Count -eq 0) {
            Write-Host ""
            Write-Host "[ACTION REQUIRED] SOURCE USER GROUP IS EMPTY" -ForegroundColor Cyan
            Write-Host "Group name: $SourceUserGroupName"
            Write-Host "Add one or more users to the group, then press any key to retry."
            $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
            $SourceUserGroupName = Read-Host "Confirm the source user group name"
            continue
        }

        Write-Host "[SUCCESS] Source user group validated. Users found: $($userMembersValidation.Count)"
        Write-Log "Source user group found. ID: $($sourceGroup.Id) Users: $($userMembersValidation.Count)" "SUCCESS"
        break
    }

    Write-Log "Checking destination device group exists."
    $destGroup = Get-SingleGroupByDisplayName -DisplayName $DestinationDeviceGroupName
    $destinationGroupExists = $null -ne $destGroup

    if (-not $destinationGroupExists) {
        Write-Log "Destination device group '$DestinationDeviceGroupName' was not found." "WARN"
        Write-Host ""
        Write-Host "Destination device group was not found." -ForegroundColor Yellow
        Write-Host "Group to create: $DestinationDeviceGroupName" -ForegroundColor Yellow
        Write-Host "This will create a mail-disabled Microsoft Entra security group intended to hold DEVICE objects." -ForegroundColor Yellow

        if (Read-YesNo -Prompt "Create this device security group now?" -DefaultNo $true) {
            $mailNickname = New-SafeMailNickname -DisplayName $DestinationDeviceGroupName
            Write-Log "Creating destination device security group '$DestinationDeviceGroupName'." "IMPORTANT"
            $destGroup = New-MgGroup -DisplayName $DestinationDeviceGroupName `
                                     -MailNickname $mailNickname `
                                     -MailEnabled:$false `
                                     -SecurityEnabled `
                                     -Description "Device security group for Endpoint DLP device scoping." `
                                     -ErrorAction Stop
            Write-Log "Create request completed. Returned group ID: $($destGroup.Id)" "SUCCESS"
            $destGroup = Wait-GroupAvailable -GroupId $destGroup.Id -TimeoutSeconds $GroupAvailabilityTimeoutSeconds -IntervalSeconds 10
            $destinationGroupExists = $true
        }
        else {
            if ($Mode -eq "Apply") { throw "Apply mode requires a destination device group. Creation was declined, so no changes were made." }
            Write-Log "Destination group creation declined. Report will continue, but destination membership comparison is unavailable." "WARN"
        }
    }
    else {
        Write-Log "Destination device group found. ID: $($destGroup.Id)" "SUCCESS"
    }

    if ($Mode -eq "CreateGroupOnly") {
        Write-Log "CreateGroupOnly mode selected. Group check/create is complete. No user/device processing will run." "SUCCESS"
        return
    }

    Write-Log "Retrieving direct source group members."
    $sourceMembers = @(Get-MgGroupMember -GroupId $sourceGroup.Id -All -ErrorAction Stop)
    $rawUserMembers = @($sourceMembers | Where-Object { $_.AdditionalProperties["@odata.type"] -eq "#microsoft.graph.user" })
    Write-Log "Source group members: $($sourceMembers.Count). Direct user members processed: $($rawUserMembers.Count). Non-user members skipped: $($sourceMembers.Count - $rawUserMembers.Count)."

    if ($rawUserMembers.Count -eq 0) { throw "The source group contains no direct user members. Nested groups are not expanded by this script." }

    $userMembers = New-Object System.Collections.Generic.List[object]
    foreach ($rawUser in $rawUserMembers) {
        try {
            $resolvedUser = Get-MgUser -UserId $rawUser.Id -Property "id,userPrincipalName,displayName" -ErrorAction Stop
            $userMembers.Add($resolvedUser)
        }
        catch {
            Write-Log "Could not resolve user details for object ID '$($rawUser.Id)'. The object will still be processed by ID. Error: $($_.Exception.Message)" "WARN"
            $userMembers.Add($rawUser)
        }
    }

    $existingDestIds = @()
    if ($destinationGroupExists) {
        Write-Log "Retrieving current destination device group membership."
        $existingDestMembers = @(Invoke-GraphWithRetry -Operation { Get-MgGroupMember -GroupId $destGroup.Id -All -ErrorAction Stop } `
                                                     -OperationName "Retrieve destination group members" `
                                                     -MaxRetries $MembershipMaxRetries `
                                                     -BaseDelaySeconds $MembershipRetryBaseDelaySeconds)
        $existingDestIds = @($existingDestMembers | ForEach-Object { $_.Id })
        Write-Log "Destination group current members: $($existingDestIds.Count)."
    }

    $reportRows = New-Object System.Collections.Generic.List[object]
    $exceptionRows = New-Object System.Collections.Generic.List[object]
    $processedDeviceIds = @{}
    $lookupErrors = 0

    Write-Log "Starting user-to-device matching." "IMPORTANT"

    foreach ($user in $userMembers) {
        $userId = Get-GraphObjectProperty -Object $user -Name "id"
        if ([string]::IsNullOrWhiteSpace($userId)) { $userId = $user.Id }

        $userUpn = Get-GraphObjectProperty -Object $user -Name "userPrincipalName"
        if ([string]::IsNullOrWhiteSpace($userUpn)) { $userUpn = $userId }

        $userDisplayName = Get-GraphObjectProperty -Object $user -Name "displayName"
        if ([string]::IsNullOrWhiteSpace($userDisplayName)) { $userDisplayName = $userUpn }

        try {
            $devices = @(Invoke-GraphWithRetry -Operation { Get-MgUserRegisteredDevice -UserId $userId -All -Property "id,displayName,operatingSystem,deviceOwnership,trustType,approximateLastSignInDateTime" -ErrorAction Stop } `
                                               -OperationName "Retrieve registered devices for $userUpn" `
                                               -MaxRetries 3 `
                                               -BaseDelaySeconds 5)
        }
        catch {
            $lookupErrors++
            $message = $_.Exception.Message
            Write-Log "Device lookup failed for '$userUpn'. Error: $message" "ERROR"
            $row = New-ReportRow -UserPrincipalName $userUpn -UserDisplayName $userDisplayName -UserId $userId -DeviceDisplayName "N/A" -DeviceObjectId "N/A" -DestinationGroupName $DestinationDeviceGroupName -AlreadyInDestinationGroup "N/A" -PlannedAction "ERROR" -Result "FAILED - DEVICE LOOKUP ERROR" -CoverageConcern "YES" -Notes $message
            $reportRows.Add($row)
            continue
        }

        if (-not $devices -or $devices.Count -eq 0) {
            Write-Log "ENDPOINT DLP COVERAGE WARNING: '$userUpn' is in the source group but has no associated device." "IMPORTANT"
            $row = New-ReportRow -UserPrincipalName $userUpn -UserDisplayName $userDisplayName -UserId $userId -DeviceDisplayName "NO DEVICE FOUND" -DeviceObjectId "N/A" -DestinationGroupName $DestinationDeviceGroupName -AlreadyInDestinationGroup "N/A" -PlannedAction "NO DEVICE FOUND" -Result "WARNING - USER HAS NO ASSOCIATED DEVICE" -CoverageConcern "YES - problematic for device-scoped Endpoint DLP" -Notes "User is in the source group, but Microsoft Graph returned no associated registered device."
            $reportRows.Add($row)
            $exceptionRows.Add($row)
            continue
        }

        $matchedDeviceForUser = $false
        foreach ($device in $devices) {
            $deviceId = Get-GraphObjectProperty -Object $device -Name "id"
            $displayName = Get-GraphObjectProperty -Object $device -Name "displayName"
            $operatingSystem = Get-GraphObjectProperty -Object $device -Name "operatingSystem"
            $ownership = Get-GraphObjectProperty -Object $device -Name "deviceOwnership"

            if ([string]::IsNullOrWhiteSpace($deviceId)) { continue }
            if ($CorporateOnly -and $ownership -ne "Company") { continue }
            if ($PersonalOnly -and $ownership -ne "Personal") { continue }

            $matchedDeviceForUser = $true

            if ($processedDeviceIds.ContainsKey($deviceId)) {
                $row = New-ReportRow -UserPrincipalName $userUpn -UserDisplayName $userDisplayName -UserId $userId -DeviceDisplayName $displayName -DeviceObjectId $deviceId -OperatingSystem $operatingSystem -Ownership $ownership -DestinationGroupName $DestinationDeviceGroupName -AlreadyInDestinationGroup "Duplicate in script run" -PlannedAction "SKIP" -Result "SKIPPED - DEVICE ALREADY PROCESSED" -CoverageConcern "REVIEW" -Notes "Same device was already processed from another user in the source group."
                $reportRows.Add($row)
                continue
            }

            $processedDeviceIds[$deviceId] = $true
            $alreadyInDestination = $false
            if ($destinationGroupExists) { $alreadyInDestination = $deviceId -in $existingDestIds }

            $alreadyText = if (-not $destinationGroupExists) { "Unknown - destination group unavailable" } elseif ($alreadyInDestination) { "Yes" } else { "No" }
            $plannedAction = if (-not $destinationGroupExists) { "NO DESTINATION GROUP" } elseif ($alreadyInDestination) { "SKIP" } else { "ADD" }
            $result = if ($Mode -ne "Apply") {
                if (-not $destinationGroupExists) { "REPORT ONLY - DESTINATION GROUP UNAVAILABLE" }
                elseif ($alreadyInDestination) { "REPORT ONLY - ALREADY A MEMBER" }
                else { "REPORT ONLY - WOULD ADD" }
            }
            elseif ($alreadyInDestination) { "SKIPPED - ALREADY A MEMBER" }
            else { "PENDING" }

            $row = New-ReportRow -UserPrincipalName $userUpn -UserDisplayName $userDisplayName -UserId $userId -DeviceDisplayName $displayName -DeviceObjectId $deviceId -OperatingSystem $operatingSystem -Ownership $ownership -DestinationGroupName $DestinationDeviceGroupName -AlreadyInDestinationGroup $alreadyText -PlannedAction $plannedAction -Result $result -CoverageConcern "No" -Notes "Matched user to registered device."
            $reportRows.Add($row)
        }

        if (-not $matchedDeviceForUser) {
            Write-Log "ENDPOINT DLP COVERAGE WARNING: '$userUpn' has device records, but none matched the ownership filter used for this run." "IMPORTANT"
            $row = New-ReportRow -UserPrincipalName $userUpn -UserDisplayName $userDisplayName -UserId $userId -DeviceDisplayName "NO DEVICE MATCH AFTER FILTER" -DeviceObjectId "N/A" -DestinationGroupName $DestinationDeviceGroupName -AlreadyInDestinationGroup "N/A" -PlannedAction "NO DEVICE MATCH" -Result "WARNING - NO DEVICE MATCHED FILTER" -CoverageConcern "YES - problematic for device-scoped Endpoint DLP" -Notes "Devices were returned, but none matched the selected filter."
            $reportRows.Add($row)
            $exceptionRows.Add($row)
        }
    }

    if ($Mode -eq "Apply" -and $destinationGroupExists) {
        Write-Log "Applying membership updates with retry logic." "IMPORTANT"
        $rowsToAdd = @($reportRows | Where-Object { $_.PlannedAction -eq "ADD" -and $_.Result -eq "PENDING" })

        foreach ($row in $rowsToAdd) {
            $added = $false
            for ($attempt = 1; $attempt -le $MembershipMaxRetries; $attempt++) {
                try {
                    $memberReference = @{ "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$($row.DeviceObjectId)" }
                    New-MgGroupMemberByRef -GroupId $destGroup.Id -BodyParameter $memberReference -ErrorAction Stop
                    $row.Result = "SUCCESS - ADDED"
                    $row.Notes = "Device added to destination group."
                    Write-Log "Added device '$($row.DeviceDisplayName)' for user '$($row.UserPrincipalName)'." "SUCCESS"
                    $added = $true
                    break
                }
                catch {
                    $message = $_.Exception.Message

                    if ($message -match "already exist" -or $message -match "added object references already exist") {
                        $row.Result = "SKIPPED - ALREADY A MEMBER"
                        $row.AlreadyInDestinationGroup = "Yes"
                        $row.Notes = "Membership already existed when add was attempted."
                        Write-Log "Device '$($row.DeviceDisplayName)' was already a member. Treating as success." "WARN"
                        $added = $true
                        break
                    }

                    $isTransient = Test-TransientGraphError -Message $message
                    if (($attempt -lt $MembershipMaxRetries) -and $isTransient) {
                        $delay = [Math]::Min(($MembershipRetryBaseDelaySeconds * $attempt), 90)
                        Write-Log "Membership update failed for '$($row.DeviceDisplayName)' attempt $attempt of $MembershipMaxRetries. Retrying in $delay seconds. Error: $message" "WARN"
                        Start-Sleep -Seconds $delay
                        continue
                    }

                    $row.Result = "FAILED - $message"
                    $row.Notes = "Membership update failed. Last error: $message"
                    Write-Log "Failed to add device '$($row.DeviceDisplayName)'. Error: $message" "ERROR"
                    break
                }
            }

            if (-not $added -and $row.Result -eq "PENDING") {
                $row.Result = "FAILED - MAX RETRIES EXCEEDED"
                $row.Notes = "Membership update did not complete after $MembershipMaxRetries attempts."
            }
        }
    }
    else {
        Write-Log "No membership changes were made because mode is $Mode." "IMPORTANT"
    }

    $reportRows | Sort-Object CoverageConcern, UserPrincipalName, DeviceDisplayName | Export-Csv -Path $mainCsvFile -NoTypeInformation -Encoding UTF8
    $exceptionRows | Sort-Object UserPrincipalName | Export-Csv -Path $exceptionsCsvFile -NoTypeInformation -Encoding UTF8

    $successAdded = @($reportRows | Where-Object { $_.Result -eq "SUCCESS - ADDED" }).Count
    $wouldAdd = @($reportRows | Where-Object { $_.Result -like "REPORT ONLY*WOULD*" }).Count
    $alreadyMember = @($reportRows | Where-Object { $_.Result -like "*ALREADY A MEMBER*" }).Count
    $failed = @($reportRows | Where-Object { $_.Result -like "FAILED*" }).Count
    $coverageWarnings = @($reportRows | Where-Object { $_.CoverageConcern -like "YES*" }).Count

    Write-Log "=== Summary ===" "IMPORTANT"
    Write-Log "Users evaluated:               $($userMembers.Count)"
    Write-Log "Users without device coverage: $coverageWarnings" "IMPORTANT"
    Write-Log "Unique devices processed:      $($processedDeviceIds.Count)"
    Write-Log "Devices added:                 $successAdded"
    Write-Log "Devices that would be added:   $wouldAdd"
    Write-Log "Devices already present:       $alreadyMember"
    Write-Log "Device lookup errors:          $lookupErrors"
    Write-Log "Failures:                      $failed"
    Write-Log "Main CSV report:               $mainCsvFile" "SUCCESS"
    Write-Log "Users-without-devices CSV:     $exceptionsCsvFile" "IMPORTANT"
    Write-Log "Log file:                      $logFile" "SUCCESS"
    Write-Log "=== Script finished in $([Math]::Round(((Get-Date) - $scriptStart).TotalSeconds, 1)) seconds ===" "IMPORTANT"
}
catch {
    Write-Log "Fatal error: $($_.Exception.Message)" "ERROR"
}
finally {
    try { Disconnect-MgGraph | Out-Null } catch { }
}
