# Import custom .NET wrapper objects for the VSS admin structures/enumerations
Add-Type -Path ($PSScriptRoot + '\Microsoft.VssAdmin.cs')

# PowerShell v2.0 does not support the RunAsAdministrator #requires directive, so this is a workaround to ensure the user knows why commands aren't working 
function Test-Administrator {
    if (-not (Get-Variable IsAdministrator -Scope Script -ea SilentlyContinue)) {
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object System.Security.Principal.WindowsPrincipal $identity        
        $Script:IsAdministrator = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
        $identity.Dispose()
    }

    return $Script:IsAdministrator
}

function New-DynamicParameterSet {
    param()    

    return New-Object System.Management.Automation.RuntimeDefinedParameterDictionary
}

function New-DynamicParameter {
    param(
        [Parameter(Mandatory=$true,Position=0)]
        [string]$Name,
        [Parameter(Position=1)]
        [type]$Type = [type][psobject],
        [Parameter()]
        [string]$ParameterSetName = '__AllParameterSets',
        [Parameter()]
        [string[]]$ValidateSet,
        [Parameter()]
        [switch]$Mandatory 
    )
    $attributes = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
    $attributes.Add((New-Object System.Management.Automation.ParameterAttribute -Property @{Mandatory=$Mandatory; ParameterSetName=$ParameterSetName}))
    
    if ($ValidateSet) {
        $attributes.Add((New-Object System.Management.Automation.ValidateSetAttribute $ValidateSet))
    }
    return New-Object System.Management.Automation.RuntimeDefinedParameter $Name, $Type, $attributes
}

function Invoke-VssAdmin {
    <#
    .SYNOPSIS
        Invokes vssadmin.exe
    .DESCRIPTION
        A wrapper function for vssadmin.exe. The process uses the same shell context as the parent.
    .PARAMETER ArgumentList
        The command-line arguments to pass to vssadmin.exe
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromRemainingArguments=$true)]
        [string[]]$ArgumentList = @('/?')
    )
    if (-not (Test-Administrator)) { 
        Write-Error "VssAdmin.exe requires administrator permissions." 
    }
    else {
        "Executing: 'vssadmin.exe' {0}" -f ($ArgumentList -join ' ') | Write-Verbose
        & vssadmin.exe $ArgumentList | Write-Output
    }
}

function Get-VssWriter {
    <#
    .SYNOPSIS
        Gets a list of VSS writers installed on the system.
    .DESCRIPTION
        A wrapper for the 'vssadmin list writers' command.
    .PARAMETER Name
        Returns the VssWrite instance with the specified name, or $null if no matching writer is found.
    .PARAMETER Include
        Optionally specify a list of VSSWriterState values to include. Any writers in a state not contained in this parameter's value will not be returned.
    .PARAMETER Exclude
        Optionally specify a list of VSSWriterState values to exclude. Any writers in a state contained in this parameter's value will not be returned.
    #>
    [CmdletBinding(DefaultParameterSetName='Include')]
    param(
        [Parameter()]
        [string]$Name,
        [Parameter(ParameterSetName='Include')]
        [Microsoft.VssAdmin.VssWriterState[]]$Include,
        [Parameter(ParameterSetName='Exclude')]
        [Microsoft.VssAdmin.VssWriterState[]]$Exclude
    )

    $output = Invoke-VssAdmin list writers
    $Matches = [regex]::Matches($output -join "`r`n", '(?<=:\s).{1,}', [System.Text.RegularExpressions.RegexOptions]::Multiline)   

    try {
        if (-not $Matches) {
            throw $output
        }
        for ($i = 0; $i -lt $Matches.Count; $i += 5) {
            $writerState = [Microsoft.VssAdmin.VssWriterState][regex]::Match($Matches[$i + 3].Value.TrimEnd(), '(?<=\[)\d(?=\])').Value
            $writerName = $Matches[$i].Value.Replace("'", '').TrimEnd()
            $nameIsMatch = $writerName -like $Name

            if (($Name -and -not $nameIsMatch) -or
                ($Include -and $Include -notcontains $writerState) -or
                ($Exclude -and $Exclude -contains $writerState)) {
                continue
            }
        
            $writerId = New-Object guid($Matches[$i + 1].Value).TrimEnd()
            $instanceId = New-Object guid($Matches[$i + 2].Value).TrimEnd()
            $lastError = $Matches[$i + 4].Value.TrimEnd()   

            New-Object Microsoft.VssAdmin.VssWriter $writerName,$writerId,$instanceId,$writerState,$lastError | Write-Output

            if ($Name -and $nameIsMatch) {
                break
            }
        }
    } catch {
        Write-Error -Message "Failed to parse output of 'vssadmin.exe list writers'" -Exception $_.Exception
    }     
}

function Get-VssWriterService {
    <#
    .SYNOPSIS
        Returns the ServiceController instance for the Windows Service that hosts the specified VSS writer(s).
    .PARAMETER Writer
        One or more VssWriter instances to return the ServiceController object for
    .PARAMETER Unique
        Some windows services host multiple VSS writers. This switch ensures only unique ServiceController objects are returned.
    .INPUTS
        Microsoft.VssAdmin.VssWriter
    .OUTPUTS 
        System.ServiceProcess.ServiceController 
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [Microsoft.VssAdmin.VssWriter[]]$Writer,
        [Parameter()]
        [switch]$Unique
    )
    begin {
        if (-not (Get-Variable VSSWriterServiceTable -ValueOnly -Scope Script -ea SilentlyContinue)) {
            $lookupNodes = ([xml](Get-Content ($PSScriptRoot + '\VSSWriterServices.xml'))).LookupTable.ChildNodes         
            New-Variable `
                -Name VSSWriterServiceTable `
                -Value ($lookupNodes | ForEach-Object -Begin {$h = @{}} -Process { $h[$_.WriterName]=$_.ServiceName } -End {$h})  `
                -Scope Script  
        }

        $history = @()

        function Get-VssWriterServiceName {
            param(
                [Parameter(Mandatory=$true, Position=0)]
                [ValidateNotNull()]
                [string]$WriterName
            )

            if (-not $Script:VSSWriterServiceTable.ContainsKey($item.Name)) {
                "No entry found for VSS writer '{0}'" -f $item.Name | Write-Error
                return ''
            }

            $Script:VSSWriterServiceTable[$item.Name] | Write-Output
        }
    }
    process {
        foreach($item in $Writer) {
            $serviceName = Get-VssWriterServiceName $item.Name
            
            if ($history -inotcontains $serviceName) {
                $history += $serviceName                 
            } elseif ($Unique) {
                continue
            }

            Get-Service -Name $history[$history.Count - 1] -ea SilentlyContinue | Write-Output 
        } 
    }
}

function Get-VssProvider {
    <#
    .SYNOPSIS
        Gets a list of VSS providers installed on the system.
    .DESCRIPTION
        A wrapper for the 'vssadmin list providers' command.
    .PARAMETER Name
        Returns the VssProvider instance with the specified name, or $null if no matching provider is found.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Name
    )
    $output = Invoke-VssAdmin list providers
    $Matches = [regex]::Matches($output -join "`r`n", '(?<=:\s).{1,}', [System.Text.RegularExpressions.RegexOptions]::Multiline)
    
    try {
        if (-not $Matches) {
            throw $output
        }
        for ($i = 0; $i -lt $Matches.Count; $i += 4) {            
            $providerName = $Matches[$i].Value.Replace("'", '').TrimEnd()
            $nameIsMatch = $providerName -like $Name

            if ($Name -and -not $nameIsMatch) {
                continue
            }
        
            $providerType = [Microsoft.VssAdmin.VssProviderType]$Matches[$i + 1].Value.TrimEnd()
            $providerId = New-Object guid $Matches[$i + 2].Value.TrimEnd()
            $version = New-Object version $Matches[$i + 3].Value.TrimEnd()             

            Write-Output (New-Object Microsoft.VssAdmin.VssProvider $providerName,$providerType,$providerId,$version)

            if ($Name -and $nameIsMatch) {
                break
            }
        }
    } catch {
         Write-Error -Message "Failed to parse output of 'vssadmin.exe list providers'" -Exception $_.Exception
    }       
}

function Get-VssVolume {
    <#
    .SYNOPSIS
        Gets a list of volumes eligible for VSS backups on the system.
    .DESCRIPTION
        A wrapper for the 'vssadmin list volumes' command.        
    #>
    [CmdletBinding()]
    param()

    $output = Invoke-VssAdmin list volumes
    $Matches = [regex]::Matches($output -join "`r`n", '(?<=:\s).{1,}', [System.Text.RegularExpressions.RegexOptions]::Multiline)   

    try {
        if (-not $Matches) {
            throw New-Object System.Exception $output
        }
        for ($i = 0; $i -lt $Matches.Count; $i += 2) {                              
            Write-Output (New-Object Microsoft.VssAdmin.VssVolume $Matches[$i].Value.TrimEnd(),$Matches[$i + 1].Value.TrimEnd())
        }
    } catch {
        Write-Error -Message "Failed to parse output of 'vssadmin.exe list volumes'." -Exception $_.Exception
    }          
}

function Get-VssShadowStorage {
    <#
    .SYNOPSIS
        Gets a list of registered VSS storage associations.
    .DESCRIPTION
        A wrapper for the 'vssadmin list shadowstorage' command.             
    #>
    [CmdletBinding()]
    param()

    DynamicParam {
        $drives = [string[]]@([System.IO.DriveInfo]::GetDrives() | Where-Object {$_.DriveType -eq 'Fixed'} | ForEach-Object {$_.Name.Substring(0,2)})
        $set = New-DynamicParameterSet 
        $set.Add('ForVolume', (New-DynamicParameter ForVolume ([string]) -ValidateSet $drives))
        $set.Add('OnVolume', (New-DynamicParameter OnVolume ([string]) -ValidateSet $drives))

        return $set
    }
    begin {
        
        $forVolFilter = if ($PSBoundParameters.ContainsKey('ForVolume')) {$PSBoundParameters['ForVolume']}
        $onVolFilter = if ($PSBoundParameters.ContainsKey('OnVolume')) {$PSBoundParameters['OnVolume']}

        function Get-DriveInfo {
            param (
                [string]$Volume
            )

            [System.IO.DriveInfo]::GetDrives() | Where-Object {$_.Name.StartsWith($Volume, [System.StringComparison]::CurrentCultureIgnoreCase)} | Write-Output
        }
        function Get-StorageValue {
            [CmdletBinding()]
            param(
                [string]$Volume,
                [Parameter(ValueFromPipelineByPropertyName=$true)]
                [string[]]$Value
            )
            begin { 
                $volMatch = [regex]::Match($Volume, "\w:(?=\)\\\\\?)")

                if (-not $volMatch.Success) {
                    throw New-Object System.ArgumentException ("Unrecognized volume: " + $Volume);
                }

                $driveInfo = Get-DriveInfo $volMatch.Value            
            }
            process {
                foreach ($item in $Value) {
                    $match = [regex]::Match($item.TrimEnd(), "(UNBOUNDED|\d{0,}\.{0,}\d{1,}\s\w{1,}(?=\s\())")
                    if (-not $match.Success) {
                        Write-Error -Exception (New-Object System.ArgumentException ('Unrecognized value: ' + $item))
                    }
                    if ($match.Value -eq 'UNBOUNDED') {
                        return New-Object Microsoft.VssAdmin.VssStorageUsage $driveInfo, -1
                    }

                    $split = $match.Value.Split()

                    switch($split[1]) {
                        B { New-Object Microsoft.VssAdmin.VssStorageUsage $driveInfo, ([long]::Parse($split[0])) | Write-Output }
                        Bytes { New-Object Microsoft.VssAdmin.VssStorageUsage $driveInfo, ([long]::Parse($split[0])) | Write-Output }
                        KB { New-Object Microsoft.VssAdmin.VssStorageUsage $driveInfo, ([long]([double]::Parse($split[0]) * 1KB)) | Write-Output }
                        MB { New-Object Microsoft.VssAdmin.VssStorageUsage $driveInfo, ([long]([double]::Parse($split[0]) * 1MB)) | Write-Output }
                        GB { New-Object Microsoft.VssAdmin.VssStorageUsage $driveInfo, ([long]([double]::Parse($split[0]) * 1GB)) | Write-Output }
                        TB { New-Object Microsoft.VssAdmin.VssStorageUsage $driveInfo, ([long]([double]::Parse($split[0]) * 1TB)) | Write-Output }
                        PB { New-Object Microsoft.VssAdmin.VssStorageUsage $driveInfo, ([long]([double]::Parse($split[0]) * 1PB)) | Write-Output }
                        Default { Write-Error  ("Unrecognized storage unit: " + $split[1]) }
                    }
                }
            }
        }
    }
    process {
        $output = Invoke-VssAdmin list shadowstorage
        $Matches = [regex]::Matches($output -join "`r`n", '(?<=:\s).{1,}$', [System.Text.RegularExpressions.RegexOptions]::Multiline)   

        try {
            if (-not $Matches) {
                throw $output
            }
            for ($i = 0; $i -lt $Matches.Count; $i += 5) {
                $forVol = $Matches[$i].Value
                if ($forVolFilter -and $forVol -notlike "*$forVolFilter*") {
                    continue
                }                
                $onVol = $Matches[$i + 1].Value
                if ($onVolFilter -and $onVol -notlike "*$onVolFilter*") {
                    continue
                } 
                $argList = @($Matches[$i].Value, $onVol) + ($Matches[($i + 2)..($i + 4)] | Get-StorageValue -Volume $onVol)

                New-Object Microsoft.VssAdmin.VssShadowStorage $argList | Write-Output
            }
        } catch {
            Write-Error -Message "Failed to parse output of 'vssadmin.exe list shadowstorage'." -Exception $_.Exception
        }
    }   
}

function Resize-VssShadowStorage {
    <#
    .SYNOPSIS
        Updates an existing VSS storage association
    .DESCRIPTION
        A wrapper for the 'vssadmin resize shadowstorage' command
    .PARAMETER InputObject
        An array of Microsoft.VssAdmin.VssShadowStorage objects to update
    .PARAMETER NewSize
        The new maximum size
    .PARAMETER As
        Specifies how NewSize should be interpreted.
    .PARAMETER Unbounded
        True if there should not be a size limit     
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$true)]
        [Microsoft.VssAdmin.VssShadowStorage[]]$InputObject,
        [Parameter(Mandatory=$true, ParameterSetName='Default')]
        [long]$NewSize,
        [ValidateSet('%', 'B', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB')]
        [string]$As = 'B',
        [Parameter(ParameterSetName='Unbounded')]
        [switch]$Unbounded                
    )
    process { 
        foreach($item in $InputObject) {
            $for = [regex]::Match($item.ForVolume, "\w:").Value
            $on = [regex]::Match($item.StorageVolume, "\w:").Value
            $size = if ($Unbounded) {'UNBOUNDED'} else {$NewSize.ToString() + $As}
            Invoke-VssAdmin resize shadowstorage /For=$for /On=$on /MaxSize=$size | Write-Verbose
        }
    }
}

function Get-VssShadowCopy {
    <#
    .SYNOPSIS
        Gets a list of the ShadowCopies available on the system.
    .DESCRIPTION
        A wrapper for the 'vssadmin list shadows' command
    #>
    [CmdletBinding()]
    param( )

    DynamicParam {
        $set = New-DynamicParameterSet
        $set.Add('Provider', (New-DynamicParameter Provider ([string]) -ValidateSet (Get-VssProvider | ForEach-Object {$_.ToString()})))

        return $set
    }
    process { }
    end {
        $output = Invoke-VssAdmin list shadows
        $Matches = [regex]::Matches($output -join "`r`n", '(?<=:\s).{1,}$', [System.Text.RegularExpressions.RegexOptions]::Multiline)

        try {
            if (-not $Matches) {
                throw New-Object System.Exception $output
            }        
            $providers = @(if ($PSBoundParameters.ContainsKey('Provider')) {Get-VssProvider -Name $PSBoundParameters['Provider']} else { Get-VssProvider })

            for($i = 0; $i -lt $Matches.Count; $i += 10) {
                $set = New-Object guid $Matches[$i].Value.TrimEnd()
                $creationTime = [datetime]::Parse($Matches[$i+1].Value.TrimEnd())
                $id = New-Object guid $Matches[$i+2].Value.TrimEnd()
                $forVol = $Matches[$i+3].Value.TrimEnd()
                $shadowVol = $Matches[$i+4].Value.TrimEnd()
                $orginalMach = $Matches[$i+5].Value.TrimEnd()
                $serviceMach = $Matches[$i+6].Value.TrimEnd()
                $provider = $providers | Where-Object {$_.Name -eq $Matches[$i+7].Value.TrimEnd().Replace("'", "")}
                if (-not $providers -and $PSBoundParameters.ContainsKey('Provider')) {
                    continue
                }
                $context = [Microsoft.VssAdmin.VssSnapshotContext]$Matches[$i+8].Value.TrimEnd()
                $attribtues = $Matches[$i+9].Value.TrimEnd() -split ',' | ForEach-Object {[Microsoft.VssAdmin.VssShadowcopyAttributes](($_ -replace '-','') -replace ' ','')}

                New-Object Microsoft.VssAdmin.VssShadowCopy $set,$creationTime,$id,$forVol,$shadowVol,$orginalMach,$serviceMach,$provider, $context, $attribtues | Write-Output
            }        
        } catch {
            Write-Error -Message "Failed to parse output of 'vssadmin.exe list shadows'." -Exception $_.Exception
        }    
    }
}

function Remove-VssShadowCopy {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(ValueFromPipeline=$true,ParameterSetName='Input')]
        [Microsoft.VssAdmin.VssShadowCopy[]]$InputObject,
        [Parameter(Mandatory=$true,ParameterSetName='Oldest')]
        [switch]$Oldest,
        [Parameter(Mandatory=$true,ParameterSetName='All')]
        [switch]$All,
        [Parameter()]
        [switch]$Force
    )

    DynamicParam {
        $drives = [string[]]@([System.IO.DriveInfo]::GetDrives() | Where-Object {$_.DriveType -eq 'Fixed'} | ForEach-Object {$_.Name.Substring(0,2)})
        $set = New-DynamicParameterSet 
        $param = New-DynamicParameter ForVolume ([string]) -ValidateSet $drives -ParameterSetName 'All'
        $param.Attributes.Add((New-Object System.Management.Automation.ParameterAttribute -Property @{ParameterSetName='Oldest'}))
        $set.Add('ForVolume', $param)

        return $set        
    }
    begin {
        $spec = if ($Oldest) {'/Oldest'} elseif($All) {'/All'}
        $yesToAll = $false
        $noToAll = $false
    }
    process {
        if ($PSBoundParameters.ContainsKey('InputObject')) {
            foreach ($item in $InputObject) {
                if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, "Delete shadow copy " + $item.ShadowCopyId)) {
                    if (-not $Force -and -not $PSCmdlet.ShouldContinue('Do you really want to delete 1 shadow copies?', $null, [ref]$yesToAll, [ref]$noToAll)) {
                        continue
                    }
                    $params += '/Shadow=' + $item.ShadowCopyId
                    Invoke-VssAdmin delete shadows /Shadow=($item.ShadowCopyId) /Quiet | Write-Verbose
                }
            }
        } else {
            if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, "Delete shadow copy " + $item.ShadowCopyId)) {
                $shadowCopies = @(Get-VssShadowCopy)
                if ($PSBoundParameters.ContainsKey('ForVolume')) {
                    $shadowCopies = $shadowCopies | Where-Object {$_.OriginalVolume -like "*$forVol*"}
                }
                if (-not $shadowCopies) {
                    "No items found that satisfy the query" | Write-Verbose
                    return
                }
                $count = if ($Oldest) {1} else {$shadowCopies.Count}
                if (-not $Force -and -not $PSCmdlet.ShouldContinue('Do you really want to delete {0} shadow copies?' -f $count, $null, [ref]$yesToAll, [ref]$noToAll)) {
                    continue
                }
                if ($forVol) {                    
                    Invoke-VssAdmin delete shadows /For=$forVol $spec /Quiet | Write-Verbose
                } else {
                    Invoke-VssAdmin delete shadows $spec /Quiet | Write-Verbose
                }                
            }
        } 
    }
}

function New-VssShadowCopy {
    [CmdletBinding()]
    param()

    throw New-Object System.NotImplementedException
}

# Export public API functions
Export-ModuleMember -Function Invoke-VssAdmin -Alias vssadmin
Export-ModuleMember -Function Get-VssWriter
Export-ModuleMember -Function Get-VssWriterService
Export-ModuleMember -Function Get-VssProvider
Export-ModuleMember -Function Get-VssVolume
Export-ModuleMember -Function Get-VssShadowStorage
Export-ModuleMember -Function Resize-VssShadowStorage
Export-ModuleMember -Function Get-VssShadowCopy
Export-ModuleMember -Function Remove-VssShadowCopy
# Export-ModuleMember -Function New-VssShadowCopy