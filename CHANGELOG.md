# Changelog

All notable changes to this script are documented here.

## 3.16.0
- Fixed a self-healing corruption-detection routine that could throw a string-escaping syntax error before it ever ran.
- Added detection for Windows Defender Controlled Folder Access (CFA) as a cause of silently corrupted module installs, independent of admin rights.
- Added automatic self-heal: if a module fails to load with a "file not found" error inside its own folder, the corrupted folder is removed and reinstalled automatically (once), strictly limited to this script's own dedicated module cache.
- Startup diagnostics now report CFA status and, if enabled, the exact executable path to allow-list.

## 3.14.0
- Added detection of the `ProviderFailToDownloadFile` PackageManagement/NuGet-provider download defect.
- Added a third module-installation fallback tier using `Install-PSResource`/`Save-PSResource` (Microsoft.PowerShell.PSResourceGet), which uses an independent download implementation from the legacy PackageManagement engine.

## 3.13.0
- Added full exception detail capture (`ErrorDetails`, `CategoryInfo`, `FullyQualifiedErrorId`, inner exception chain) for module-installation failures instead of a generic top-level message.
- Added a PSGallery reachability/trust pre-check to distinguish repository-level problems from module- or folder-specific ones.
- Added a self-healing retry for a leftover partial/corrupted download in the dedicated fallback folder.

## 3.12.0
- Reworked automatic module installation to install and load a missing module in the same run without requiring a new PowerShell session, by resolving the freshly-installed module's location via `Get-InstalledModule` instead of relying on the stale module-autodiscovery cache.
- Added a dedicated, non-Documents fallback install folder and automatic `PSModulePath` registration.

## 3.11.0
- Attempted a NuGet provider pre-install for CurrentUser scope (superseded by the 3.12.0 rework above once the true root cause was confirmed).

## 3.10.0
- `-InstallMissingModules` now defaults to **on**, so missing modules are detected and installed automatically without needing to know in advance whether they're present. Use `-InstallMissingModules:$false` to opt out.

## 3.9.1
- Fixed a bug where the Graph disconnect-on-exit logic could throw its own "term not recognized" error if the script failed before Microsoft.Graph.Authentication was ever imported.

## 3.9.0
- (Superseded by 3.9.1 in the same session.)

## 3.8.0
- Added detection of elevated/admin PowerShell sessions and proactive guidance for the known Microsoft Graph SDK/Windows WAM broker limitation that can cause interactive browser sign-in to hang with no visible window.
- Added a best-effort `Set-MgGraphOption -EnableLoginByWAM $false` call for older SDK versions where it still has an effect.

## 3.7.0
- Fixed Device Code authentication silently hanging: the sign-in code/URL message is now piped to `Out-Host` instead of `Out-Null`, per known Microsoft Graph SDK behavior (the message is written to the success output stream, not directly to the host).

## 3.6.0
- Added automatic Microsoft Graph disconnect on script exit (success or failure), unless `-SkipGraphConnect` was used.

## 3.5.0
- **Confirmed root cause fix**: replaced `return @($results)` with `return $results.ToArray()` in device retrieval, fixing a Windows PowerShell 5.1 dynamic-binder defect (`PSEnumerableBinder`/`PSToObjectArrayBinder`) that threw "Argument types do not match" when wrapping a `List<T>` with `@()`.
- Added full diagnostic capture (exception type, `ScriptStackTrace`, .NET `StackTrace`, inner exceptions) for this failure class.

## 3.3.0
- Removed `-Property` from `Get-MgUserRegisteredDevice`/`Get-MgUserOwnedDevice`/`Get-MgGroupMember` (target group) calls, after confirming these cmdlets return polymorphic `directoryObject` results where device-specific property names in `-Property` can throw `ArgumentException` on some SDK versions. All fields are read safely via `Get-GraphObjectValue`, which falls back to `AdditionalProperties` regardless.
- Fixed a `Dictionary<TKey,TValue>.Contains()` method-binding ambiguity (`Contains` argument count mismatch) by switching to `ContainsKey()` when reading Graph SDK `AdditionalProperties`.
- Made the target device group optional: if missing, the script offers to create it automatically, waits for replication, and continues. The source user group remains mandatory and is never auto-created.

## 3.2.0 and earlier
- Initial script structure: group resolution by display name/object ID, transitive/direct membership, device relationship modes (Registered/Owned/Both), add/remove sync logic, retry-with-backoff, CSV reporting, `-WhatIf`/`-Confirm` support, and the original (later hardened) authentication and module-installation logic.
