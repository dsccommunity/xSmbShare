$script:DSCModuleName = 'xSmbShare'
$script:DSCResourceName = 'MSFT_xSmbShare'

# Unit Test Template Version: 1.2.2
$script:moduleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if ( (-not (Test-Path -Path (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests'))) -or `
     (-not (Test-Path -Path (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests\TestHelper.psm1'))) )
{
    & git @('clone','https://github.com/PowerShell/DscResource.Tests.git',(Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests'))
}

Import-Module -Name (Join-Path -Path $script:moduleRoot -ChildPath (Join-Path -Path 'DSCResource.Tests' -ChildPath 'TestHelper.psm1')) -Force

$TestEnvironment = Initialize-TestEnvironment `
    -DSCModuleName $script:DSCModuleName `
    -DSCResourceName $script:DSCResourceName `
    -ResourceType 'Mof' `
    -TestType Unit

#endregion HEADER

function Invoke-TestSetup
{
}

function Invoke-TestCleanup
{
    # Restore the test environment
    Restore-TestEnvironment -TestEnvironment $TestEnvironment
}


# Begin Testing
try
{
    
    Invoke-TestSetup

    InModuleScope $script:DSCResourceName {

        # Define test user accounts
        $mockUserAccounts = @(
        "User1",
        "User2",
        "User3",
        "User4",
        "User5"
        )

        # Declare mock objects
        $mockChangeAccess = @("User1")
        $mockReadAccess = @("User2")
        $mockFullAccess = @("User3", "User5")
        $mockNoAcess = @("User4")
        $mockDefaultChangeAccess = @("User2")
        $mockDefaultReadAccess = @("User3")
        $mockDefaultFullAccess = @("User1")
        $mockDefaultNoAccess = @()


        $mockSmbShare = (
            New-Object -TypeName Object |
            Add-Member -MemberType NoteProperty -Name 'Name' -Value 'DummyShare' -PassThru |
            Add-Member -MemberType NoteProperty -Name 'ScopeName' -Value '*' -PassThru |
            Add-Member -MemberType NoteProperty -Name 'Path' -Value 'c:\temp' -PassThru |
            Add-Member -MemberType NoteProperty -Name 'Description' 'Dummy share for unit testing' -PassThru |
            Add-Member -MemberType NoteProperty -Name 'ConcurrentUserLimit' -Value 10 -PassThru |
            Add-Member -MemberType NoteProperty -Name 'EncryptData' -Value $false -PassThru |
            Add-Member -MemberType NoteProperty -Name 'FolderEnumerationMode' -Value "AccessBased" -PassThru | # 0 AccessBased | 1 Unrestricted, but method expects text
            Add-Member -MemberType NoteProperty -Name 'SharedState' -Value 1 -PassThru | # 0 Pending | 1 Online | 2 Offline
            Add-Member -MemberType NoteProperty -Name 'ShadowCopy' -Value $false -PassThru |
            Add-Member -MemberType NoteProperty -Name 'Special' -Value $false -PassThru 
        )
       
        $mockSmbShareAccess = @((
            New-Object -TypeName Object |
            Add-Member -MemberType NoteProperty -Name 'Name' -Value 'DummyShare' -PassThru |
            Add-Member -MemberType NoteProperty -Name 'ScopName' -Value '*' -PassThru |
            #Add-Member -MemberType NoteProperty -Name 'AccountName' -Value "$($env:COMPUTERNAME)\User1" -PassThru |
            Add-Member -MemberType NoteProperty -Name 'AccountName' -Value @("User1") -PassThru |
            Add-Member -MemberType NoteProperty -Name 'AccessControlType' -Value 'Allow' -PassThru |
            Add-Member -MemberType NoteProperty -Name 'AccessRight' -Value 'Full' -PassThru
            ),
            (
            New-Object -TypeName Object |
            Add-Member -MemberType NoteProperty -Name 'Name' -Value 'DummyShare' -PassThru |
            Add-Member -MemberType NoteProperty -Name 'ScopName' -Value '*' -PassThru |
            #Add-Member -MemberType NoteProperty -Name 'AccountName' -Value "$($env:COMPUTERNAME)\User2" -PassThru |
            Add-Member -MemberType NoteProperty -Name 'AccountName' -Value @("User2") -PassThru |
            Add-Member -MemberType NoteProperty -Name 'AccessControlType' -Value 'Allow' -PassThru |
            Add-Member -MemberType NoteProperty -Name 'AccessRight' -Value 'Change' -PassThru
            ),
            (
            New-Object -TypeName Object |
            Add-Member -MemberType NoteProperty -Name 'Name' -Value 'DummyShare' -PassThru |
            Add-Member -MemberType NoteProperty -Name 'ScopName' -Value '*' -PassThru |
            #Add-Member -MemberType NoteProperty -Name 'AccountName' -Value "$($env:COMPUTERNAME)\User3" -PassThru |
            Add-Member -MemberType NoteProperty -Name 'AccountName' -Value @("User3") -PassThru |
            Add-Member -MemberType NoteProperty -Name 'AccessControlType' -Value 'Allow' -PassThru |
            Add-Member -MemberType NoteProperty -Name 'AccessRight' -Value 'Read' -PassThru
            )
        )

        Describe 'MSFT_xSmbShare\Get-TargetResource' -Tag 'Get' {

            Context 'When the system is in the desired state' {
                BeforeAll {
                    # Per context-block initialization
                }

                # Mock the command to get the acl
                Mock -CommandName Get-SmbShare -MockWith { return @($mockSmbShare)}
                Mock -CommandName Get-SmbShareAccess -MockWith { return @($mockSmbShareAccess)}

                # Set testParameters
                $testParameters = @{
                    Name = $mockSmbShare.Name
                    Path = $mockSmbShare.Path
                }

                # Call Get-TargetResource
                

                It 'Should mock call to Get-SmbShare and return membership' {
                    $result = Get-TargetResource @testParameters
                    $result.ChangeAccess[0] | Should Be ($mockSmbShareAccess | Where-Object {$_.AccessRight -eq 'Change'}).AccountName
                    $result.ReadAccess[0] | Should Be ($mockSmbShareAccess | Where-Object {$_.AccessRight -eq 'Read'}).AccountName
                    $result.FullAccess[0] | Should Be ($mockSmbShareAccess | Where-Object {$_.AccessRight -eq 'Full'}).AccountName
                    $result.NoAccess[0] | Should BeNullOrEmpty
                }

                It 'Should call the mock function Get-SmbShare' {
                    $result = Get-TargetResource @testParameters
                    Assert-MockCalled Get-SmbShare -Exactly -Times 1 -Scope It
                }

                It 'Should Call the mock function Get-SmbShareAccess' {
                    $result = Get-TargetResource @testParameters
                    Assert-MockCalled Get-SmbShareAccess -Exactly -Times 1 -Scope It
                }
            }
        }

        Describe 'MSFT_xSmbShare\Set-TargetResource' -Tag 'Set' {
            Context 'When the system is not in the desired state' {
                BeforeAll {
                    # Per context-block initialization
                }

                # Set the testParameter collection
                $testParameters = @{
                    ChangeAccess = $mockChangeAccess
                    ReadAccess = $mockReadAccess
                    FullAccess = $mockFullAccess
                    NoAccess = $mockNoAccess
                    Name = $mockSmbShare.Name
                    Path = $mockSmbShare.Path
                    Description = $mockSmbShare.Description
                    ConcurrentUserLimit = $mockSmbShare.ConcurrentUserLimit
                    EncryptData = $mockSmbShare.EncryptData
                    FolderEnumerationMode = $mockSmbShare.FolderEnumerationMode
                    Ensure = "Present"
                }

                # Init the script variables
                $script:ChangeAccess = @()
                $script:ReadAccess = @()
                $script:FullAccess = @()
                $script:NoAccess = @()
                $script:ChangeAccess += $mockDefaultChangeAccess
                $script:ReadAccess += $mockDefaultReadAccess
                $script:FullAccess += $mockDefaultFullAccess
                $script:NoAccess += $mockDefaultNoAccess


                # Set mock function calls
                Mock -CommandName Get-SmbShare -MockWith { return @($mockSmbShare)}
                Mock -CommandName Get-SmbShareAccess -MockWith { return @($mockSmbShareAccess)}
                Mock -CommandName Set-SmbShare -MockWith { return $null}
                Mock -CommandName Grant-SmbShareAccess -MockWith {
                    # Declare local array -- use of this variable was necessary as the script: context was losing the fact it was an array in the mock
                    $localArray = @()

                    switch($AccessPermission)
                    {
                        "Change"
                        {
                            $localArray += $script:ChangeAccess
                            if ($localArray -notcontains $UserName)
                            {
                                $localArray += $UserName
                            }
                            
                            $script:ChangeAccess = $localArray
                            break
                        }
                        "Read"
                        {
                            $localArray += $script:ReadAccess
                            if($localArray -notcontains $UserName)
                            {
                                $localArray += $UserName
                            }
                            $script:ReadAccess = $localArray
                            break
                        }
                        "Full"
                        {
                            $localArray += $script:FullAccess
                            if($localArray -notcontains $UserName)
                            {
                                $localArray += $UserName
                            }
                            $script:FullAccess = $localArray
                            break
                        }
                    }
                }
                Mock Block-SmbShareAccess -MockWith {
                    $script:NoAccess += $UserName
                }
                Mock Revoke-SmbShareAccess -MockWith {
                    switch($AccessPermission)
                    {
                        "Change"
                        {
                            # Remove from array
                            $script:ChangeAccess = $script:ChangeAccess | Where-Object {$_ -ne $UserName}
                            break
                        }
                        "Read"
                        {
                            $script:ReadAccess = $script:ReadAccess | Where-Object {$_ -ne $UserName}
                            break
                        }
                        "Full"
                        {
                            $script:FullAccess = $script:FullAccess | Where-Object {$_ -ne $UserName}
                            break
                        }
                    }
                }
                Mock -CommandName Unblock-SmbShareAccess -MockWith {
                    $script:NoAccess = $script:NoAccess | Where-Object {$_ -ne $UserName}
                }

                

                It 'Should alter permissions' {
                    $result = Set-TargetResource @testParameters
                    $script:ChangeAccess | Should Be $mockChangeAccess
                    $script:ReadAccess | Should Be $mockReadAccess
                    $script:FullAccess | Should Be $mockFullAccess
                    #$script:NoAccess | Should Be $mockNoAcess
                }
                
                It 'Should call the mock function Get-SmbShare' {
                    $result = Set-TargetResource @testParameters
                    Assert-MockCalled Get-SmbShare -Exactly -Times 1 -Scope It
                }

                It 'Should Call the mock function Get-SmbShareAccess' {
                    $result = Set-TargetResource @testParameters
                    Assert-MockCalled Get-SmbShareAccess -Exactly -Times 4 -Scope It
                }

                It 'Should call the mock function Set-SmbShare' {
                    $result = Set-TargetResource @testParameters
                    Assert-MockCalled Set-SmbShare -Exactly -Times 1 -Scope It
                }
            }
        }

        Describe 'MSFT_xSmbShare\Test-TargetResource' -Tag 'Test' {
            Context 'When the system is not in the desired state' {

                # Set the testParameter collection
                $testParameters = @{
                    ChangeAccess = $mockChangeAccess
                    ReadAccess = $mockReadAccess
                    FullAccess = $mockFullAccess
                    NoAccess = $mockNoAcess
                    Name = $mockSmbShare.Name
                    Path = $mockSmbShare.Path
                    Description = $mockSmbShare.Description
                    ConcurrentUserLimit = $mockSmbShare.ConcurrentUserLimit
                    EncryptData = $mockSmbShare.EncryptData
                    FolderEnumerationMode = $mockSmbShare.FolderEnumerationMode
                    Ensure = "Present"
                }

                BeforeAll {
                    # Per context-block initialization
                }

                # Set mock function calls
                Mock -CommandName Get-SmbShare -MockWith { return @($mockSmbShare)}
                Mock -CommandName Get-SmbShareAccess -MockWith { return @($mockSmbShareAccess)}
                Mock -CommandName Get-TargetResource -MockWith { return @{
        Name = $mocksmbShare.Name
        Path = $mocksmbShare.Path
        Description = $mocksmbShare.Description
        ConcurrentUserLimit = $mocksmbShare.ConcurrentUserLimit
        EncryptData = $mocksmbShare.EncryptData
        FolderEnumerationMode = $mocksmbShare.FolderEnumerationMode                
        ShareState = $mocksmbShare.ShareState
        ShareType = $mocksmbShare.ShareType
        ShadowCopy = $mocksmbShare.ShadowCopy
        Special = $mocksmbShare.Special
        ChangeAccess = $mockDefaultchangeAccess
        ReadAccess = $mockDefaultreadAccess
        FullAccess = $mockDefaultfullAccess
        NoAccess = $mockDefaultnoAccess     
        Ensure = "Present"
        }
    }
                
                It 'Should return false' {
                    # Call the Test-TargetResource
                    $result = Test-TargetResource @testParameters
                   
                    # Result should be false
                    $result | Should be $false
                }
            }

            Context 'When the system is in the desired state' {

                # Set the testParameter collection
                $testParameters = @{
                    ChangeAccess = $mockDefaultChangeAccess
                    ReadAccess = $mockDefaultReadAccess
                    FullAccess = $mockDefaultFullAccess
                    #NoAccess = $null
                    Name = $mockSmbShare.Name
                    Path = $mockSmbShare.Path
                    Description = $mockSmbShare.Description
                    ConcurrentUserLimit = $mockSmbShare.ConcurrentUserLimit
                    EncryptData = $mockSmbShare.EncryptData
                    FolderEnumerationMode = $mockSmbShare.FolderEnumerationMode
                    Ensure = "Present"
                }

                # Set mock function calls
                Mock -CommandName Get-SmbShare -MockWith { return @($mockSmbShare)}
                Mock -CommandName Get-SmbShareAccess -MockWith { return @($mockSmbShareAccess)}               
                Mock -CommandName Get-TargetResource -MockWith { return @{
                    Name = $mocksmbShare.Name
                    Path = $mocksmbShare.Path
                    Description = $mocksmbShare.Description
                    ConcurrentUserLimit = $mocksmbShare.ConcurrentUserLimit
                    EncryptData = $mocksmbShare.EncryptData
                    FolderEnumerationMode = $mocksmbShare.FolderEnumerationMode                
                    ShareState = $mocksmbShare.ShareState
                    ShareType = $mocksmbShare.ShareType
                    ShadowCopy = $mocksmbShare.ShadowCopy
                    Special = $mocksmbShare.Special
                    ChangeAccess = $mockDefaultchangeAccess
                    ReadAccess = $mockDefaultreadAccess
                    FullAccess = $mockDefaultfullAccess
                    NoAccess = $mockDefaultnoAccess     
                    Ensure = "Present"
                    }
                }
            
                
                It 'Should return true' {
                    $result = Test-TargetResource @testParameters

                    # Result should be true
                    $result | Should be $true
                }
                
                It 'Should call the mock function Get-TargetResource' {
                    $result = Test-TargetResource @testParameters
                    Assert-MockCalled Get-TargetResource -Exactly -Times 1 -Scope It
                }

            }
        }
    }
}
finally
{
    Invoke-TestCleanup
}
