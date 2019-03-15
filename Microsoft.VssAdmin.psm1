# Import custom .NET wrapper objects for the VSS admin structures/enumerations
Add-Type -Path ($PSScriptRoot + '\Microsoft.VssAdmin.cs')
Add-Type -Path C:\Users\zack\Documents\WindowsPowerShell\Modules\Microsoft.VssAdmin\Microsoft.VssAdmin.cs

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
        [psobject[]]$ValidateSet,
        [Parameter()]
        [switch]$Mandatory 
    )
    $attributes = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
    if ($Mandatory) {
        $attributes.Add((New-Object Parameter -Property @{Mandatory=$Mandatory}))
    }
    if ($ValidateSet) {
        $attributes.Add((New-Object ValidateSet $ValidateSet))
    }
    return New-Object System.Management.Automation.RuntimeDefinedParameter $Name, $Type, $attributes
}

function Add-DynamicParameter {
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [System.Management.Automation.RuntimeDefinedParameterDictionary]$Dictionary,
        [Parameter(Mandatory=$true,Position=0)]
        [System.Management.Automation.RuntimeDefinedParameter]$Parameter
    )

    process {
        $Dictionary.Add($Parameter.Name, $Parameter)
        $Dictionary | Write-Output
    }
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
    "Executing: 'vssadmin.exe' $($ArgumentList -join ' ')" | Write-Verbose
    & vssadmin.exe $ArgumentList | Write-Output
}

function Get-VssWriter {
    <#
    .SYNOPSIS
        Gets a list of VSS writers installed on the system.
    .DESCRIPTION
        A wrapper for the 'vssadmin list writers' command.
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
        "Failed to parse output of 'vssadmin.exe list writers'`r`n" | Write-Error -Exception $_.Exception
    }     
}

function Get-VssWriterService {
    <#
    .SYNOPSIS
        Returns the ServiceController instance for the Windows Service that hosts the specified VSS writer(s).
    .PARAMETER Writer
        One or more VssWriter instances to return the ServiceController object for
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
         "Failed to parse output of 'vssadmin.exe list providers'" | Write-Error -Exception $_.Exception
    }       
}

function Get-VssVolume {
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
        "Failed to parse output of 'vssadmin.exe list volumes'." | Write-Error -Exception $_.Exception
    }          
}

function Get-VssShadowStorage {
    [CmdletBinding()]
    param()

    $output = Invoke-VssAdmin list shadowstorage
    $Matches = [regex]::Matches($output -join "`r`n", '(?<=:\s).{1,}', [System.Text.RegularExpressions.RegexOptions]::Multiline)   

    try {
        if (-not $Matches) {
            throw $output
        }
        for ($i = 0; $i -lt $Matches.Count; $i += 5) {                              
            [Microsoft.VssAdmin.VssShadowStorage]::FromMatches($Matches[$i], $Matches[$i + 1],$Matches[$i + 2],$Matches[$i + 3],$Matches[$i + 4]) | Write-Output
        }
    } catch {
        "Failed to parse output of 'vssadmin.exe list shadowstorage'." | Write-Error -Exception $_.Exception
    }   
}

function Resize-VssShadowStorage {
    [CmdletBinding()]
    param(
        [Parameter()]
        [Microsoft.VssAdmin.VssShadowStorage]$InputObject        
    )
    begin { throw New-Object System.NotImplementedException }
    process { }
}

function Get-VssShadowCopy {
    [CmdletBinding()]
    param( )

    DynamicParam {
        return New-DynamicParameterSet | Add-DynamicParameter -Parameter (New-DynamicParameter Provider ([Microsoft.VssAdmin.VssShadowCopy]) -ValidateSet (Get-VssProvider))
    }
    process { }
    end {
        $output = Invoke-VssAdmin list shadows
        $Matches = [regex]::Matches($output -join "`r`n", '(?<=:\s).{1,}$', [System.Text.RegularExpressions.RegexOptions]::Multiline)

        try {
            if (-not $Matches) {
                throw New-Object System.Exception $output
            }        
            $providers = @(if ($PSBoundParameters.ContainsKey('Provider')) {$PSBoundParameters['Provider']} else { Get-VssProvider })

            for($i = 0; $i -lt $Matches.Count; $i += 10) {
                $set = New-Object guid $Matches[$i].Value.TrimEnd()
                $creationTime = [datetime]::Parse($Matches[$i+1].Value.TrimEnd())
                $id = New-Object guid $Matches[$i+2].Value.TrimEnd()
                $forVol = $Matches[$i+3].Value.TrimEnd()
                $shadowVol = $Matches[$i+4].Value.TrimEnd()
                $orginalMach = $Matches[$i+5].Value.TrimEnd()
                $serviceMach = $Matches[$i+6].Value.TrimEnd()
                $provider = $providers | Where {$_.Name -eq $Matches[$i+7].Value.TrimEnd().Replace("'", "")}
                if (-not $providers -and $PSBoundParameters.ContainsKey('Provider')) {
                    continue
                }
                $context = [Microsoft.VssAdmin.VssSnapshotContext]$Matches[$i+8].Value.TrimEnd()
                $attribtues = $Matches[$i+9].Value.TrimEnd() -split ',' | Foreach {[Microsoft.VssAdmin.VssShadowcopyAttributes](($_ -replace '-','') -replace ' ','')}

                New-Object Microsoft.VssAdmin.VssShadowCopy $set,$creationTime,$id,$forVol,$shadowVol,$orginalMach,$serviceMach,$provider, $context, $attribtues | Write-Output
            }        
        } catch {
            Write-Error -Message "Failed to parse output of 'vssadmin.exe list shadows'." -Exception $_.Exception
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
# Export-ModuleMember -Function Resize-VssShadowStorage
Export-ModuleMember -Function Get-VssShadowCopy
# Export-ModuleMember -Function New-VssShadowCopy

# SIG # Begin signature block
# MIIV6wYJKoZIhvcNAQcCoIIV3DCCFdgCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUwHJYBQwNxuyKUxm3F6TDXuZI
# Lbeggg+qMIIEmTCCA4GgAwIBAgIPFojwOSVeY45pFDkH5jMLMA0GCSqGSIb3DQEB
# BQUAMIGVMQswCQYDVQQGEwJVUzELMAkGA1UECBMCVVQxFzAVBgNVBAcTDlNhbHQg
# TGFrZSBDaXR5MR4wHAYDVQQKExVUaGUgVVNFUlRSVVNUIE5ldHdvcmsxITAfBgNV
# BAsTGGh0dHA6Ly93d3cudXNlcnRydXN0LmNvbTEdMBsGA1UEAxMUVVROLVVTRVJG
# aXJzdC1PYmplY3QwHhcNMTUxMjMxMDAwMDAwWhcNMTkwNzA5MTg0MDM2WjCBhDEL
# MAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UE
# BxMHU2FsZm9yZDEaMBgGA1UEChMRQ09NT0RPIENBIExpbWl0ZWQxKjAoBgNVBAMT
# IUNPTU9ETyBTSEEtMSBUaW1lIFN0YW1waW5nIFNpZ25lcjCCASIwDQYJKoZIhvcN
# AQEBBQADggEPADCCAQoCggEBAOnpPd/XNwjJHjiyUlNCbSLxscQGBGue/YJ0UEN9
# xqC7H075AnEmse9D2IOMSPznD5d6muuc3qajDjscRBh1jnilF2n+SRik4rtcTv6O
# KlR6UPDV9syR55l51955lNeWM/4Og74iv2MWLKPdKBuvPavql9LxvwQQ5z1IRf0f
# aGXBf1mZacAiMQxibqdcZQEhsGPEIhgn7ub80gA9Ry6ouIZWXQTcExclbhzfRA8V
# zbfbpVd2Qm8AaIKZ0uPB3vCLlFdM7AiQIiHOIiuYDELmQpOUmJPv/QbZP7xbm1Q8
# ILHuatZHesWrgOkwmt7xpD9VTQoJNIp1KdJprZcPUL/4ygkCAwEAAaOB9DCB8TAf
# BgNVHSMEGDAWgBTa7WR0FJwUPKvdmam9WyhNizzJ2DAdBgNVHQ4EFgQUjmstM2v0
# M6eTsxOapeAK9xI1aogwDgYDVR0PAQH/BAQDAgbAMAwGA1UdEwEB/wQCMAAwFgYD
# VR0lAQH/BAwwCgYIKwYBBQUHAwgwQgYDVR0fBDswOTA3oDWgM4YxaHR0cDovL2Ny
# bC51c2VydHJ1c3QuY29tL1VUTi1VU0VSRmlyc3QtT2JqZWN0LmNybDA1BggrBgEF
# BQcBAQQpMCcwJQYIKwYBBQUHMAGGGWh0dHA6Ly9vY3NwLnVzZXJ0cnVzdC5jb20w
# DQYJKoZIhvcNAQEFBQADggEBALozJEBAjHzbWJ+zYJiy9cAx/usfblD2CuDk5oGt
# Joei3/2z2vRz8wD7KRuJGxU+22tSkyvErDmB1zxnV5o5NuAoCJrjOU+biQl/e8Vh
# f1mJMiUKaq4aPvCiJ6i2w7iH9xYESEE9XNjsn00gMQTZZaHtzWkHUxY93TYCCojr
# QOUGMAu4Fkvc77xVCf/GPhIudrPczkLv+XZX4bcKBUCYWJpdcRaTcYxlgepv84n3
# +3OttOe/2Y5vqgtPJfO44dXddZhogfiqwNGAwsTEOYnB9smebNd0+dmX+E/CmgrN
# Xo/4GengpZ/E8JIh5i15Jcki+cPwOoRXrToW9GOUEB1d0MYwggTQMIIDuKADAgEC
# AgEHMA0GCSqGSIb3DQEBCwUAMIGDMQswCQYDVQQGEwJVUzEQMA4GA1UECBMHQXJp
# em9uYTETMBEGA1UEBxMKU2NvdHRzZGFsZTEaMBgGA1UEChMRR29EYWRkeS5jb20s
# IEluYy4xMTAvBgNVBAMTKEdvIERhZGR5IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9y
# aXR5IC0gRzIwHhcNMTEwNTAzMDcwMDAwWhcNMzEwNTAzMDcwMDAwWjCBtDELMAkG
# A1UEBhMCVVMxEDAOBgNVBAgTB0FyaXpvbmExEzARBgNVBAcTClNjb3R0c2RhbGUx
# GjAYBgNVBAoTEUdvRGFkZHkuY29tLCBJbmMuMS0wKwYDVQQLEyRodHRwOi8vY2Vy
# dHMuZ29kYWRkeS5jb20vcmVwb3NpdG9yeS8xMzAxBgNVBAMTKkdvIERhZGR5IFNl
# Y3VyZSBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgLSBHMjCCASIwDQYJKoZIhvcNAQEB
# BQADggEPADCCAQoCggEBALngyxDUr3a91JNi6zBkuIEIbMME2WIXji//PmXPj85i
# 5jxSHNoWRUtVq3hrY4NikM4PaWyZyBoUi0zMRTPqiNyeo68r/oBhnXlXxM8u9D8w
# PF1H/JoWvMM3lkFRjhFLVPgovtCMvvAwOB7zsCb4Zkdjbd5xJkePOEdT0UYdtOPc
# AOpFrL28cdmqbwDb280wOnlPX0xH+B3vW8LEnWA7sbJDkdikM07qs9YnT60liqXG
# 9NXQpq50BWRXiLVEVdQtKjo++Li96TIKApRkxBY6UPFKrud5M68MIAd/6N8EOcJp
# AmxjUvp3wRvIdIfIuZMYUFQ1S2lOvDvTSS4f3MHSUvsCAwEAAaOCARowggEWMA8G
# A1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBRAwr0njsw0
# gzCiM9f7bLPwtCyAzjAfBgNVHSMEGDAWgBQ6moUHEGcotu/2vQVBbiDBlNoP3jA0
# BggrBgEFBQcBAQQoMCYwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmdvZGFkZHku
# Y29tLzA1BgNVHR8ELjAsMCqgKKAmhiRodHRwOi8vY3JsLmdvZGFkZHkuY29tL2dk
# cm9vdC1nMi5jcmwwRgYDVR0gBD8wPTA7BgRVHSAAMDMwMQYIKwYBBQUHAgEWJWh0
# dHBzOi8vY2VydHMuZ29kYWRkeS5jb20vcmVwb3NpdG9yeS8wDQYJKoZIhvcNAQEL
# BQADggEBAAh+bJMQyDi4lqmQS/+hX08E72w+nIgGyVCPpnP3VzEbvrzkL9v4utNb
# 4LTn5nliDgyi12pjczG19ahIpDsILaJdkNe0fCVPEVYwxLZEnXssneVe5u8MYaq/
# 5Cob7oSeuIN9wUPORKcTcA2RH/TIE62DYNnYcqhzJB61rCIOyheJYlhEG6uJJQEA
# D83EG2LbUbTTD1Eqm/S8c/x2zjakzdnYLOqum/UqspDRTXUYij+KQZAjfVtL/qQD
# WJtGssNgYIP4fVBBzsKhkMO77wIv0hVU7kQV2Qqup4oz7bEtdjYm3ATrn/dhHxXc
# h2/uRpYoraEmfQoJpy4Eo428+LwEMAEwggY1MIIFHaADAgECAgkArJEY2MPJmfgw
# DQYJKoZIhvcNAQELBQAwgbQxCzAJBgNVBAYTAlVTMRAwDgYDVQQIEwdBcml6b25h
# MRMwEQYDVQQHEwpTY290dHNkYWxlMRowGAYDVQQKExFHb0RhZGR5LmNvbSwgSW5j
# LjEtMCsGA1UECxMkaHR0cDovL2NlcnRzLmdvZGFkZHkuY29tL3JlcG9zaXRvcnkv
# MTMwMQYDVQQDEypHbyBEYWRkeSBTZWN1cmUgQ2VydGlmaWNhdGUgQXV0aG9yaXR5
# IC0gRzIwHhcNMTgwNDA2MTcwMDAwWhcNMjAwNTIxMTgxODAyWjB2MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTESMBAGA1UEBxMJU2FuIERpZWdvMR4w
# HAYDVQQKDBVLJlIgTmV0d29yayBTb2x1dGlvbnMxHjAcBgNVBAMMFUsmUiBOZXR3
# b3JrIFNvbHV0aW9uczCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAKle
# dgP5ZAWWJeMbK4NFkuhmbuE2KHl3E5lx33+Kn3g+cB7zAfE3cDA2H8vwD3f+xyQX
# VzqX2tYZdCquDYfn4OX+mdqvH14uFUN2xiRh2i5NeZ40Rx9eG/eRbr/v7yRhbU/Z
# 7IIOaqQJZLPvd+cK20F/MFCy9FlDxyf/sbOhMASVYZV83P54vRyFGA9tNYw+rYlE
# BqkarezxHoQxeb6vi5ZJNkAX+ApbdUqnfOTbYri+ClfqEA0Tqcdq/9WokOKjhNkZ
# nmQhr08VzhNP4UJ2w3LABo+JEpL+2/DHfe7pDt00Y72C9y/JmJl0LNJCEqmDercJ
# ZwtDtfWRJL/zd/ihGjZhSeVV3qjSsgvemdvqdq+KnkONBypMCljGhJHl2U5vIHp3
# syjft5ppoShTzqhWKkVPM5HMGrUNUIk+05m/X1VmOloi4Q3dDWgcCE4LqEHs7yEi
# 0JGBZQm5JjKzu+yTN4BLpLm+/mcJCIHQ490tM9KcPU9rx1/HiNycApTbQhHFA2DL
# QvKErAaQmtATjhUvzYZ/gAkznbH1qal5rlsrK4vR+Ui0fBuXZWk6WdFRMlhjxui8
# 2hOM4xeVJ5DAOlORpHWSjhaS8KKQfObLvYCP3xx2LWdkli6Pt+1NVGa29jB7WCJg
# z4eoxhm6GV/f425CPhLD0XVKdpWT67E0Bs6ein0jAgMBAAGjggGFMIIBgTAMBgNV
# HRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMA4GA1UdDwEB/wQEAwIHgDA1
# BgNVHR8ELjAsMCqgKKAmhiRodHRwOi8vY3JsLmdvZGFkZHkuY29tL2dkaWcyczUt
# NC5jcmwwXQYDVR0gBFYwVDBIBgtghkgBhv1tAQcXAjA5MDcGCCsGAQUFBwIBFito
# dHRwOi8vY2VydGlmaWNhdGVzLmdvZGFkZHkuY29tL3JlcG9zaXRvcnkvMAgGBmeB
# DAEEATB2BggrBgEFBQcBAQRqMGgwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmdv
# ZGFkZHkuY29tLzBABggrBgEFBQcwAoY0aHR0cDovL2NlcnRpZmljYXRlcy5nb2Rh
# ZGR5LmNvbS9yZXBvc2l0b3J5L2dkaWcyLmNydDAfBgNVHSMEGDAWgBRAwr0njsw0
# gzCiM9f7bLPwtCyAzjAdBgNVHQ4EFgQUX1HwQx43cXlN4fGGXzA/YGHdphkwDQYJ
# KoZIhvcNAQELBQADggEBABpC4dDgQ+lx1vdcchfKsL60Keh+MJQg4lgc/z52BpCg
# Js0dAuCNHJbIDBgzfdcd/JE7v+DGS/okRDSBcjInuXCBK1Ogr6maqi+Pc18XMUN/
# RyJR3FUqgfAGUzvL8pGh5MEnDMz9AXWqQmjFJTNHyvBADORpbhM6yJwnVvu8QTWg
# z18PNpuDHglsiwEmKxmcBn5q4SUyETomdg5drJtWfHZIZy/l5s+Wyr5NSQS1/3Yd
# xGU45TAjBOEHw4AcKWrWqlo7dJ+HUTNgVdW0xKJ5Ir+Qi7RaVz0ys23Z6/5FU18S
# aOePg8W9CfZ0toHlXb0VkONrfRvElquCW8bVfmHFtNgxggWrMIIFpwIBATCBwjCB
# tDELMAkGA1UEBhMCVVMxEDAOBgNVBAgTB0FyaXpvbmExEzARBgNVBAcTClNjb3R0
# c2RhbGUxGjAYBgNVBAoTEUdvRGFkZHkuY29tLCBJbmMuMS0wKwYDVQQLEyRodHRw
# Oi8vY2VydHMuZ29kYWRkeS5jb20vcmVwb3NpdG9yeS8xMzAxBgNVBAMTKkdvIERh
# ZGR5IFNlY3VyZSBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgLSBHMgIJAKyRGNjDyZn4
# MAkGBSsOAwIaBQCgeDAYBgorBgEEAYI3AgEMMQowCKACgAChAoAAMBkGCSqGSIb3
# DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEV
# MCMGCSqGSIb3DQEJBDEWBBTiRG9pqmsXyQ/ZDsWwIxDjc8lz3DANBgkqhkiG9w0B
# AQEFAASCAgARtEGz8JZq+krnAWCsX81YkI5lbHWQrgcZgXbFI9LaEQnmBls31XI+
# 6N3/CZadWY0qinRsjrzLc/5LpC5gSuHvF3ZIZ4K8SNMc7r3xVgEiNBo8hHUeDcP/
# ocD1rh0D6DGoT2kCZnxVON2wFUMeOTHqRVdoRm3CJ7QYM8z5XL/f7iSh1q7mNqbs
# /vs4ABqUNZBBRaOQRXSaqhBDtxb0jA4KXf9BA67c7ePI0G8NcukgFRADy/fEnGFU
# ylJ/1ZQShZHLNQNhCBq9QuNZ4ziAQnWNRH9n/aoZe2n9xIU1n2OMfSr6aD7N8vgm
# /TQWFQlvd/Hn6Z5UfDP2/FrkHwPCmvl+MQT31ymX0SLevslBfxpHY/uC9xdUcaA6
# uePptTYKULkE0Vy05zjYE5A9Pk2EhsGLc88m4Js65qdNI2lf5PeBdVZEOWuXLw31
# QN/Az5DbUQeZ00dLtn4/HIqHMqrz79aqG4JLGEvdTxVcftcY1/NFOr3NBU5pG1p6
# Af/JDOhFlH5x+KbOagwJVn25OdtNQB8veHrB8GUwx8D9PRpLhENrR9zrKsRTYLAz
# lxuMzQe0BKBAGB1jKKTzWak2PLSwq8RwhtW7Lo82ixUDzsM+bvuVWDBInRuM4WlH
# 6hlnG9eolmsfXN38iyYTvFbY45v8DjopdPu5xkLFDla6YLy0ECshAKGCAkMwggI/
# BgkqhkiG9w0BCQYxggIwMIICLAIBATCBqTCBlTELMAkGA1UEBhMCVVMxCzAJBgNV
# BAgTAlVUMRcwFQYDVQQHEw5TYWx0IExha2UgQ2l0eTEeMBwGA1UEChMVVGhlIFVT
# RVJUUlVTVCBOZXR3b3JrMSEwHwYDVQQLExhodHRwOi8vd3d3LnVzZXJ0cnVzdC5j
# b20xHTAbBgNVBAMTFFVUTi1VU0VSRmlyc3QtT2JqZWN0Ag8WiPA5JV5jjmkUOQfm
# MwswCQYFKw4DAhoFAKBdMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZI
# hvcNAQkFMQ8XDTE5MDMxNDIxMTk0NFowIwYJKoZIhvcNAQkEMRYEFBX1O+WMMhhr
# R/IhYAqY1NWbvFu9MA0GCSqGSIb3DQEBAQUABIIBAMEKt3++sKC+gIM5vyTguKDp
# Vto1BkRg1JxNhnIbGiAPQMeldxIHh4a8eOg4TtipQLMoN4pEBzTw3SCzG7V4iqeU
# 0OdknB7p3fKhjlmgi3hr0yqEjMUQ5PotaqBs+dg/O0ZZRJz0H8bRs2HmQswyV2vg
# 4xiagYmyLAXgi1/Tma0SO2g8MTQGj19i9skDJeUAXPro0f8AIZ4RPjcq/FhsY120
# uGPfw+9TbOHmRxQ3G90H1KxyVGq19YnR+kbklh5jpN3ijWQii7Q1okH+FvdTX+lN
# wpUbB1haYjcAcVZnGbQJlTZ2EzRkJzOgYc1p/fvKSMsoHdiZKZeAqCzKR7ehGx4=
# SIG # End signature block
