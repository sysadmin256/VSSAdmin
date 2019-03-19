# Microsoft.VssAdmin
PowerShell module for the [Vssadmin](https://docs.microsoft.com/windows-server/administration/windows-commands/vssadmin) utility

### Table of Contents
  * [Command \-\> Function Lookup](#command---function-lookup)
  * [Examples](#examples)
  * [Download & Install](#download--install)

### Command \-\> Function Lookup
| VssAdmin Command | Wrapper Function | Status |
|:-----------------|:-----------------|:-------|
| add shadowstorage | Add-VssShadowStorage | Complete |
| create shadow | New-VssShadowCopy | Complete |
| [delete shadows](https://docs.microsoft.com/windows-server/administration/windows-commands/vssadmin-delete-shadows) | Remove-VssShadowCopy | Complete |
| list providers | Get-VssProvider| Complete |
| [list shadows](https://docs.microsoft.com/windows-server/administration/windows-commands/vssadmin-list-shadows) | Get-VssShadowCopy | Complete |
| list shadowstorage | Get-VssShadowStorage | Complete |
| list volumes | Get-VssVolume | Complete |
| [list writers](https://docs.microsoft.com/windows-server/administration/windows-commands/vssadmin-list-writers) | Get-VssWriter | Complete |
| resize shadowstorage | Resize-VssShadowStorage | Complete |

### Examples

##### Example \#1
Get all VSS writers not in the `VssWriterState.Stable` state
```PowerShell
PS> Get-VssWriter -Exclude Stable
```
##### Example \#2
Get writers in a failed state and restart the host Windows Service
```PowerShell
PS> Get-VssWriter | Where-Object {$_.State -like 'Failed*'} | Get-VssWriterService -Unique | Restart-Service -Force
```
##### Example \#3
Update the MaxSize for a ShadowCopy storage association to 5%
```PowerShell
PS> Get-VssShadowStorage -ForVolume C: | Resize-VssShadowStorage -NewSize 5 -As %
```
Update the MaxSize to UNBOUNDED
```PowerShell
PS> Get-VssShadowStorage -ForVolume C: | Resize-VssShadowStorage -Unbounded
```

##### Example \#4
List all ShadowCopies created by a specified Provider
```PowerShell
PS> Get-VssShadowCopy -Provider 'Microsoft Software Shadow Copy provider 1.0'
```

### Download \& Install

Download the latest version of the module files [here]()
