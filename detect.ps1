[string]$SidecarMiPolicy = 
@"
<?xml version="1.0"?>
<AppLockerPolicy Version="1">
    <RuleCollection Type="Dll" EnforcementMode="AuditOnly">
        <FilePathRule Id="86f235ad-3f7b-4121-bc95-ea8bde3a5db5" Name="Dummy Rule" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
            <Conditions>
                <FilePathCondition Path="%OSDRIVE%\ThisWillBeBlocked.dll" />
            </Conditions>
        </FilePathRule>
        <RuleCollectionExtensions>
            <ThresholdExtensions>
                <Services EnforcementMode="Enabled" />
            </ThresholdExtensions>
            <RedstoneExtensions>
                <SystemApps Allow="Enabled" />
            </RedstoneExtensions>
        </RuleCollectionExtensions>
    </RuleCollection>

    <RuleCollection Type="Exe" EnforcementMode="AuditOnly">
        <FilePathRule Id="9420c496-046d-45ab-bd0e-455b2649e41e" Name="Dummy Rule" Description="" UserOrGroupSid="S-1-1-0" Action="Deny">
            <Conditions>
                <FilePathCondition Path="%OSDRIVE%\ThisWillBeBlocked.exe" />
            </Conditions>
        </FilePathRule>
        <RuleCollectionExtensions>
            <ThresholdExtensions>
                <Services EnforcementMode="Enabled" />
            </ThresholdExtensions>
            <RedstoneExtensions>
                <SystemApps Allow="Enabled" />
            </RedstoneExtensions>
        </RuleCollectionExtensions>
    </RuleCollection>

    <RuleCollection Type="ManagedInstaller" EnforcementMode="AuditOnly">
        <FilePublisherRule Id="3cf97403-1b4a-4492-8e70-98436cf78983" Name="MICROSOFT.MANAGEMENT.SERVICES.INTUNEWINDOWSAGENT.EXE version 1.37.200.8 exactly in MICROSOFT INTUNE from O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" Description="2" UserOrGroupSid="S-1-1-0" Action="Allow">
            <Conditions>
                <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="*" BinaryName="MICROSOFT.MANAGEMENT.SERVICES.INTUNEWINDOWSAGENT.EXE">
                    <BinaryVersionRange LowSection="1.37.200.8" HighSection="*" />
                </FilePublisherCondition>
            </Conditions>
        </FilePublisherRule>
    </RuleCollection>
</AppLockerPolicy>
"@


function VerifyCompliance([xml]$MIPolicy)
{
    # Load the current effective AppLocker policy
    try
    {
        [xml]$effectivePolicyXml = Get-AppLockerPolicy -Effective -Xml -ErrorVariable ev -ErrorAction SilentlyContinue
    }
    catch
    {
        Write-Error('Get-AppLockerPolicy failed. ' + $_.Exception.Message)
        exit 1
    }

    [xml]$desiredPolicy = $MIPolicy
    $binaryName = $desiredPolicy.AppLockerPolicy.childnodes.FilePublisherRule.Conditions.FilePublisherCondition.BinaryName

    $miNode = $effectivePolicyXml.childnodes.RuleCollection.FilePublisherRule.Conditions.FilePublisherCondition | Where-Object {$_.Binaryname -eq $binaryName}
   
    if(-not $miNode)
    {
        Write-Host('Intune Managed Installer policy not installed')
        return $false
    }

    # New version?
    $currentVersion = $minode.ParentNode.ParentNode.Description
    $desiredversion = $desiredPolicy.AppLockerPolicy.childnodes.FilePublisherRule.Description

    if($desiredversion -ne $currentVersion)
    {
        Write-Host('Upgrade from version ' + $currentVersion + ' to ' + $desiredversion)
        return $false
    }
    else
    {
        Write-Host('Same version (' + $currentVersion + '), no need to install')
        return $true
    }
}


# Execution flow starts here


# Check if it contains MI policy and if the MI policy has rules for sidecar
try
{
    $compliant = VerifyCompliance($SidecarMiPolicy)
}
catch
{
    Write-Error('Failed to verify AppLocker policy compliance. ' + $_.Exception.Message)
    exit 1
}


if($compliant)
{
   # sidecar is set as the managed installer
   Write-Host("Sidecar is set as the managed installer.")

   # Check if the registry value is there and set it if it is not
   if(!(Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\IntuneManagementExtension\SideCarPolicies" -Name "ManagedInstallerEnabled" -ErrorAction Ignore))
   {
      Write-Host("ManagedInstallerEnabled in registry is missing")
      Set-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\IntuneManagementExtension\SideCarPolicies" -Name "ManagedInstallerEnabled" -Value 1
   }

   exit 0
}
else
{
   # sidecar is not set as the managed insatller
   Write-Host("Sidecar is not set as a managed installer.")

   # Check if the registry value is there and remove it if it is there
   if(Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\IntuneManagementExtension\SideCarPolicies" -Name "ManagedInstallerEnabled" -ErrorAction Ignore)
   {
      Write-Host("ManagedInstallerEnabled should not be present")
      Remove-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\IntuneManagementExtension\SideCarPolicies" -Name "ManagedInstallerEnabled"
   }

   exit 1
}
# SIG # Begin signature block
# MIIjlAYJKoZIhvcNAQcCoIIjhTCCI4ECAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBIa3nZl+z60Kgn
# myenV7gq9oD3MM8Y7fR2DEKmn1dePKCCDXYwggX0MIID3KADAgECAhMzAAAB3vl+
# gOdHKPWkAAAAAAHeMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjAxMjE1MjEzMTQ0WhcNMjExMjAyMjEzMTQ0WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQC42o7GuqPBrC9Z9N+JtpXANgk2m77zmZSuuBKQmr5pZRmQCht/u/V21N5nwBWK
# NGwCZNdI98dyYGYORRZgrMOh8JWxDBjLMQYtqklGLw5ZPw3OCGCIM2ZU0snDlvZ3
# nKwys5NtPlY4shJxcVM2dhMnXhRTqvtexmeWpfmvtiop7jJn2Sdq0iDybDyU2vMz
# nH2ASetgjvuW2eP4d6zQXlboTBBu1ZxTv/aCRrWCWUPge8lHr3wtiPJHMyxmRHXT
# ulS2VksZ6iI9RLOdlqup9UOcnKRaj1usJKjwADu75+fegAZ4HPWSEXXmpBmuhvbT
# Euwa04eiL7ZKbG3mY9EqpiJ7AgMBAAGjggFzMIIBbzAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUbrkwVx/G26M/PsNzHEotPDOdBMcw
# RQYDVR0RBD4wPKQ6MDgxHjAcBgNVBAsTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEW
# MBQGA1UEBRMNMjMwMDEyKzQ2MzAwODAfBgNVHSMEGDAWgBRIbmTlUAXTgqoXNzci
# tW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3JsMGEG
# CCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3J0
# MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIBAHBTJKafCqTZswwxIpvl
# yU+K/+9oxjswaMqV+yGkRLa7LDqf917yb+IHjsPphMwe0ncDkpnNtKazW2doVHh3
# wMNXUYX6DzyVg1Xr/MTYaai0/GkPR/RN4MSBfoVBDzXJSisnYEWlK1TbI1J1mNTU
# iyiaktveVsH3xQyOVXQEpKFW17xYoHGjYm8s5v22mRE/ShVgsEW9ckxeQbJPCkPc
# PiqD4eXwPguTxv06Pwxva8lsjsPDvo2EgwozBCNGRAxsv2pEl0bh+yOtaFpfQWG7
# yMskiLQwWWoWFyuzm6yiKmZ/jdfO98xR1bFUhQMdwQoMi0lCUMx6YQJj1WpNUTDq
# X0ttJGny2aPWsoOgZ5fzKHNfCowOA+7hLc6gCVRBzyMN/xvV19aKymPt8I/J5gqA
# ZCQT19YgNKyhHUYS4GnFyMr/0GCezE8kexDGeQ3JX1TpHQvcz/dghK30fWM9z44l
# BjNcMV/HtTuefSFsr9tCp53wVaw65LudxSjH+/a2zUa85KKCBzj/GU4OhDaa5Wd4
# 8jr0JSm/515Ynzm1Xje5Ai/qo9xaGCrjrVcJUxBXd/SZPorm3HN6U1aJnL2Kw6nY
# 8Rs205CIWT28aFTecMQ6+KnMt1NZR4pogBnnpWSLc92JMbUd1Z6IbauU6U/oOjyl
# WOtkYUKbyE7EvK9GwUQXMds/MIIHejCCBWKgAwIBAgIKYQ6Q0gAAAAAAAzANBgkq
# hkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5
# IDIwMTEwHhcNMTEwNzA4MjA1OTA5WhcNMjYwNzA4MjEwOTA5WjB+MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYDVQQDEx9NaWNyb3NvZnQg
# Q29kZSBTaWduaW5nIFBDQSAyMDExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEAq/D6chAcLq3YbqqCEE00uvK2WCGfQhsqa+laUKq4BjgaBEm6f8MMHt03
# a8YS2AvwOMKZBrDIOdUBFDFC04kNeWSHfpRgJGyvnkmc6Whe0t+bU7IKLMOv2akr
# rnoJr9eWWcpgGgXpZnboMlImEi/nqwhQz7NEt13YxC4Ddato88tt8zpcoRb0Rrrg
# OGSsbmQ1eKagYw8t00CT+OPeBw3VXHmlSSnnDb6gE3e+lD3v++MrWhAfTVYoonpy
# 4BI6t0le2O3tQ5GD2Xuye4Yb2T6xjF3oiU+EGvKhL1nkkDstrjNYxbc+/jLTswM9
# sbKvkjh+0p2ALPVOVpEhNSXDOW5kf1O6nA+tGSOEy/S6A4aN91/w0FK/jJSHvMAh
# dCVfGCi2zCcoOCWYOUo2z3yxkq4cI6epZuxhH2rhKEmdX4jiJV3TIUs+UsS1Vz8k
# A/DRelsv1SPjcF0PUUZ3s/gA4bysAoJf28AVs70b1FVL5zmhD+kjSbwYuER8ReTB
# w3J64HLnJN+/RpnF78IcV9uDjexNSTCnq47f7Fufr/zdsGbiwZeBe+3W7UvnSSmn
# Eyimp31ngOaKYnhfsi+E11ecXL93KCjx7W3DKI8sj0A3T8HhhUSJxAlMxdSlQy90
# lfdu+HggWCwTXWCVmj5PM4TasIgX3p5O9JawvEagbJjS4NaIjAsCAwEAAaOCAe0w
# ggHpMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRIbmTlUAXTgqoXNzcitW2o
# ynUClTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYD
# VR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBRyLToCMZBDuRQFTuHqp8cx0SOJNDBa
# BgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2Ny
# bC9wcm9kdWN0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3JsMF4GCCsG
# AQUFBwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraS9jZXJ0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3J0MIGfBgNV
# HSAEgZcwgZQwgZEGCSsGAQQBgjcuAzCBgzA/BggrBgEFBQcCARYzaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraW9wcy9kb2NzL3ByaW1hcnljcHMuaHRtMEAGCCsG
# AQUFBwICMDQeMiAdAEwAZQBnAGEAbABfAHAAbwBsAGkAYwB5AF8AcwB0AGEAdABl
# AG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQBn8oalmOBUeRou09h0ZyKb
# C5YR4WOSmUKWfdJ5DJDBZV8uLD74w3LRbYP+vj/oCso7v0epo/Np22O/IjWll11l
# hJB9i0ZQVdgMknzSGksc8zxCi1LQsP1r4z4HLimb5j0bpdS1HXeUOeLpZMlEPXh6
# I/MTfaaQdION9MsmAkYqwooQu6SpBQyb7Wj6aC6VoCo/KmtYSWMfCWluWpiW5IP0
# wI/zRive/DvQvTXvbiWu5a8n7dDd8w6vmSiXmE0OPQvyCInWH8MyGOLwxS3OW560
# STkKxgrCxq2u5bLZ2xWIUUVYODJxJxp/sfQn+N4sOiBpmLJZiWhub6e3dMNABQam
# ASooPoI/E01mC8CzTfXhj38cbxV9Rad25UAqZaPDXVJihsMdYzaXht/a8/jyFqGa
# J+HNpZfQ7l1jQeNbB5yHPgZ3BtEGsXUfFL5hYbXw3MYbBL7fQccOKO7eZS/sl/ah
# XJbYANahRr1Z85elCUtIEJmAH9AAKcWxm6U/RXceNcbSoqKfenoi+kiVH6v7RyOA
# 9Z74v2u3S5fi63V4GuzqN5l5GEv/1rMjaHXmr/r8i+sLgOppO6/8MO0ETI7f33Vt
# Y5E90Z1WTk+/gFcioXgRMiF670EKsT/7qMykXcGhiJtXcVZOSEXAQsmbdlsKgEhr
# /Xmfwb1tbWrJUnMTDXpQzTGCFXQwghVwAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAAHe+X6A50co9aQAAAAAAd4wDQYJYIZIAWUDBAIB
# BQCgga4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIOGU88CFiqWeiU0XYoIvi0bW
# VgMcD8iIYmCQD9q2+p4BMEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEB
# BQAEggEADj5zkbg9qFxeaCXQVRWg4hPaESPDOeEGxSTaWJZ95v+487RDKGQ7RA5C
# IRAqrbGLK1pIwgWBI7AKnXlK5A9498LS4JMh9BD8ewe0kFa1+2tT3kn6eysRfXGb
# W04XsED5bDNfgGeWKQUtmXknlHSw2RZHvx3oVkg54HFk4mS3g5Plo9cI0gqamdmB
# N5rGUIiyS79wwvZlVbOddMBnqCzVZ/2BQ5ktLJ9Flrr71976dDScMo2OzdoLlLf/
# jR2vcBawVOIIZ+aV0eutTqx0/hj+yeLP8r8K70xmwA1Q73Zx008w7n0NH5kTtftw
# q7BJIBmSwK6+hI/HqRdJcZ7bsbA8FqGCEv4wghL6BgorBgEEAYI3AwMBMYIS6jCC
# EuYGCSqGSIb3DQEHAqCCEtcwghLTAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFZBgsq
# hkiG9w0BCRABBKCCAUgEggFEMIIBQAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFl
# AwQCAQUABCDjH7RScp/u8sYr875GB4mnhG2YJeP2GnzE5GbleLKCegIGYUiuYZVZ
# GBMyMDIxMTAxMTA0NDc0Ni4zMDdaMASAAgH0oIHYpIHVMIHSMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJl
# bGFuZCBPcGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNO
# OkQwODItNEJGRC1FRUJBMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBT
# ZXJ2aWNloIIOTTCCBPkwggPhoAMCAQICEzMAAAFBr39Sl1zy3EUAAAAAAUEwDQYJ
# KoZIhvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjAx
# MDE1MTcyODI3WhcNMjIwMTEyMTcyODI3WjCB0jELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEtMCsGA1UECxMkTWljcm9zb2Z0IElyZWxhbmQgT3Bl
# cmF0aW9ucyBMaW1pdGVkMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjpEMDgyLTRC
# RkQtRUVCQTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZTCC
# ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAPIqy6i9vHWpfjyVJlCTsL2J
# /7DghM0M2co/eF2xT7UYQ4T42oL7yjr9RoDKDrl75KTN7jOROu78jgj8aoUwM6uw
# JN85BF1wb+yaDPF5tMeVHJwJKVIhKNHsnEZem52CAdypWVt7s+CXNr9hVdCghpC6
# 76nyj/Ff4toVcjfOeDno1qcfMBlGszOAmFFaMHIBA3O+jmPl2uFtuwwmSZtn/aJe
# AY0i/m9i/0/J/yxBpJ2lMcEkEzdS0ArfrgQwgEnelUEeQiyyVbejAS9FtTZWlsRA
# CcJSHcgZ0tYoS70YNY3PylGXtLERXQ934Sq4z2nN4aMtNOxb6+hqNFieKa9qyXUC
# AwEAAaOCARswggEXMB0GA1UdDgQWBBQtKD8sbi6Q/UVwa/XPDTtBBRLGxDAfBgNV
# HSMEGDAWgBTVYzpcijGQ80N7fEYbxTNoWoVtVTBWBgNVHR8ETzBNMEugSaBHhkVo
# dHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNUaW1T
# dGFQQ0FfMjAxMC0wNy0wMS5jcmwwWgYIKwYBBQUHAQEETjBMMEoGCCsGAQUFBzAC
# hj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1RpbVN0YVBD
# QV8yMDEwLTA3LTAxLmNydDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUF
# BwMIMA0GCSqGSIb3DQEBCwUAA4IBAQBSet8ifdgoagoKXsQ+PKJL4hrguIpDbL5s
# JQknrdbBabyRMyyQfHExeM+KkE8/ALELXHsOpgFZkAmA7vX+XntdcV49S8B2LGRp
# 0rPzn0bpdVSpmOdTkKaryuTvwreH7NCG5c6PHsjiycoE5Pe2l1QOFM6vBm5S+y0O
# V4sAGOOOjDgC5zVxaPyqvbb84qcGNWHEZ/55TEPm/djoiy5h1TItsAFDkYihb2gH
# 2Fo4UHftqhyzLHaTZbsAW1nuxReQAbA6NB0TjFsgoMXS0N76q9wzEh92ViooqxbL
# 1iZnIX2TxkTm8KrM70lzxZjwWfaPnq/uFKC1fudBlp50JMux1YC5MIIGcTCCBFmg
# AwIBAgIKYQmBKgAAAAAAAjANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMx
# EzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoT
# FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3Qg
# Q2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTAwHhcNMTAwNzAxMjEzNjU1WhcNMjUw
# NzAxMjE0NjU1WjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQ
# MA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
# MSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDCCASIwDQYJ
# KoZIhvcNAQEBBQADggEPADCCAQoCggEBAKkdDbx3EYo6IOz8E5f1+n9plGt0VBDV
# pQoAgoX77XxoSyxfxcPlYcJ2tz5mK1vwFVMnBDEfQRsalR3OCROOfGEwWbEwRA/x
# YIiEVEMM1024OAizQt2TrNZzMFcmgqNFDdDq9UeBzb8kYDJYYEbyWEeGMoQedGFn
# kV+BVLHPk0ySwcSmXdFhE24oxhr5hoC732H8RsEnHSRnEnIaIYqvS2SJUGKxXf13
# Hz3wV3WsvYpCTUBR0Q+cBj5nf/VmwAOWRH7v0Ev9buWayrGo8noqCjHw2k4GkbaI
# CDXoeByw6ZnNPOcvRLqn9NxkvaQBwSAJk3jN/LzAyURdXhacAQVPIk0CAwEAAaOC
# AeYwggHiMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBTVYzpcijGQ80N7fEYb
# xTNoWoVtVTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYw
# DwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvXzpoY
# xDBWBgNVHR8ETzBNMEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtp
# L2NybC9wcm9kdWN0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYIKwYB
# BQUHAQEETjBMMEoGCCsGAQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20v
# cGtpL2NlcnRzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNydDCBoAYDVR0gAQH/
# BIGVMIGSMIGPBgkrBgEEAYI3LgMwgYEwPQYIKwYBBQUHAgEWMWh0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9QS0kvZG9jcy9DUFMvZGVmYXVsdC5odG0wQAYIKwYBBQUH
# AgIwNB4yIB0ATABlAGcAYQBsAF8AUABvAGwAaQBjAHkAXwBTAHQAYQB0AGUAbQBl
# AG4AdAAuIB0wDQYJKoZIhvcNAQELBQADggIBAAfmiFEN4sbgmD+BcQM9naOhIW+z
# 66bM9TG+zwXiqf76V20ZMLPCxWbJat/15/B4vceoniXj+bzta1RXCCtRgkQS+7lT
# jMz0YBKKdsxAQEGb3FwX/1z5Xhc1mCRWS3TvQhDIr79/xn/yN31aPxzymXlKkVIA
# rzgPF/UveYFl2am1a+THzvbKegBvSzBEJCI8z+0DpZaPWSm8tv0E4XCfMkon/VWv
# L/625Y4zu2JfmttXQOnxzplmkIz/amJ/3cVKC5Em4jnsGUpxY517IW3DnKOiPPp/
# fZZqkHimbdLhnPkd/DjYlPTGpQqWhqS9nhquBEKDuLWAmyI4ILUl5WTs9/S/fmNZ
# JQ96LjlXdqJxqgaKD4kWumGnEcua2A5HmoDF0M2n0O99g/DhO3EJ3110mCIIYdqw
# UB5vvfHhAN/nMQekkzr3ZUd46PioSKv33nJ+YWtvd6mBy6cJrDm77MbL2IK0cs0d
# 9LiFAR6A+xuJKlQ5slvayA1VmXqHczsI5pgt6o3gMy4SKfXAL1QnIffIrE7aKLix
# qduWsqdCosnPGUFN4Ib5KpqjEWYw07t0MkvfY3v1mYovG8chr1m1rtxEPJdQcdeh
# 0sVV42neV8HR3jDA/czmTfsNv11P6Z0eGTgvvM9YBS7vDaBQNdrvCScc1bN+NR4I
# uto229Nfj950iEkSoYIC1zCCAkACAQEwggEAoYHYpIHVMIHSMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJl
# bGFuZCBPcGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNO
# OkQwODItNEJGRC1FRUJBMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBT
# ZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQCq5b8ptQqriKEHK853C75A9VqVA6CBgzCB
# gKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMA0GCSqGSIb3DQEBBQUA
# AgUA5Q4y8jAiGA8yMDIxMTAxMTExNTAxMFoYDzIwMjExMDEyMTE1MDEwWjB3MD0G
# CisGAQQBhFkKBAExLzAtMAoCBQDlDjLyAgEAMAoCAQACAgE0AgH/MAcCAQACAhIR
# MAoCBQDlD4RyAgEAMDYGCisGAQQBhFkKBAIxKDAmMAwGCisGAQQBhFkKAwKgCjAI
# AgEAAgMHoSChCjAIAgEAAgMBhqAwDQYJKoZIhvcNAQEFBQADgYEAj/4CIpEbEV0B
# PhBaVKi8mQjbj6n7WhX/ZOH40hl2oJA/+TWw0tfnihIPUhhFk1J89sInOG0hJI1e
# VM6N0soX29NL8PGBFFCqWQcm2zOsCXtgysCWFb6zXSoFJpf86jVipd284rXU+CAw
# yydjhZkapF5MQL+mMON81VmzBl1JzAQxggMNMIIDCQIBATCBkzB8MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQg
# VGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAUGvf1KXXPLcRQAAAAABQTANBglghkgB
# ZQMEAgEFAKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3
# DQEJBDEiBCDUw8Rwu4dalvUk5XJJjb88gk5MsxeFPfpfZhbsuhVY2TCB+gYLKoZI
# hvcNAQkQAi8xgeowgecwgeQwgb0EIFE/ATyM6nN0nnB0TyygbVtLzjp0/u/IWlqP
# l3MVXq3eMIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMA
# AAFBr39Sl1zy3EUAAAAAAUEwIgQg3A2zCSelkZ/FIJlUr9cXN5MuS92p3h0usi2B
# 1wdjo5YwDQYJKoZIhvcNAQELBQAEggEAhKdX/F6nxJtMSH9Uy5sWu7LQfe7zLZvz
# 8vJFBc6cPz7VlU7RaBHvbDEwPF3MmB7lRnduRpx9gYS4pCD4A+/9WhRbi2BI6pox
# T7fTQntTim7f0s2HiQEJfuh0Qqb1vP792HcuKfvu0X3Gsgd7F0v4O8rsbj4kH4Sy
# x2GdPZdxyGfe1T0RUBpcrpBBZ0wS13v71N4u6qk6czTte9FufSS9yn28gO0Xm079
# z5EDMGmqEmP6mkefqgEK3wcxTqvAU5coh5VAuO7nUoNvi3VMsABzKeQv/9n/HWXf
# /c4hjvGVUKa5qHJOMTkcz8mlN7ffiqY0+md/vFBbq4mO3nYczjBPhg==
# SIG # End signature block
