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
    # Set up the mock users to test with
    Create-MockUserObjects -userCollection $mockUserAccounts
}

function Invoke-TestCleanup
{
    # Remove the users we were using for testing
    Remove-MockUserObjects -userCollection $mockUserAccounts

    # Restore the test environment
    Restore-TestEnvironment -TestEnvironment $TestEnvironment
}

function Create-MockUserObjects
{
    # Define parameters
    Param($userCollection)

    # Loop through collection and create user accounts
    $userCollection | ForEach-Object {New-LocalUser -Name $_ -Description "Dummy account $_" -NoPassword}
}

function Remove-MockUserObjects
{
    # Define parameters
    Param($userCollection)

    # Loop through collectionand remove users
    $userCollection | ForEach-Object {Remove-LocalUser -Name $_}
}


# Begin Testing
try
{
    # Define test user accounts
    $mockUserAccounts = @()
    $mockUserAccounts += "User1"
    $mockUserAccounts += "User2"
    $mockUserAccounts += "User3"
    $mockUserAccounts += "User4"
    $mockUserAccounts += "User5"

    # Declare mock objects
    $mockChangeAccess = @("User1")
    $mockReadAccess = @("User2")
    $mockFullAccess = @("User3", "User5")
    $mockNoAcess = @("User4")
    $mockDefaultChangeAccess = @("User2")
    $mockDefaultReadAccess = @("User3")
    $mockDefaultFullAccess = @("User1")
    $mockDefaultNoAccess = @()
    
    Invoke-TestSetup

    InModuleScope $script:DSCResourceName {
        # TODO: Optionally create any variables here for use by your tests

        # TODO: Complete the Describe blocks below and add more as needed.
        # The most common method for unit testing is to test by function. For more information
        # check out this introduction to writing unit tests in Pester:
        # https://www.simple-talk.com/sysadmin/powershell/practical-powershell-unit-testing-getting-started/#eleventh
        # You may also follow one of the patterns provided in the TestsGuidelines.md file:
        # https://github.com/PowerShell/DscResources/blob/master/TestsGuidelines.md

        $mockSmbShare = (
            New-Object -TypeName Object |
            Add-Member -MemberType NoteProperty -Name 'Name' -Value 'DummyShare' -PassThru |
            Add-Member -MemberType NoteProperty -Name 'ScopeName' -Value '*' -PassThru |
            Add-Member -MemberType NoteProperty -Name 'Path' -Value 'c:\temp' -PassThru |
            Add-Member -MemberType NoteProperty -Name 'Description' 'Dummy share for unit testing' -PassThru |
            Add-Member -MemberType NoteProperty -Name 'ConcurrentUserLimit' -Value 10 -PassThru |
            Add-Member -MemberType NoteProperty -Name 'EncryptData' -Value $false -PassThru |
            Add-Member -MemberType NoteProperty -Name 'FolderEnumerationMode' -Value 0 -PassThru | # 0 AccessBased | 1 Unrestricted
            Add-Member -MemberType NoteProperty -Name 'SharedState' -Value 1 -PassThru | # 0 Pending | 1 Online | 2 Offline
            Add-Member -MemberType NoteProperty -Name 'ShadowCopy' -Value $false -PassThru |
            Add-Member -MemberType NoteProperty -Name 'Special' -Value $false -PassThru 
        )

        $mockSmbShareAccess = @((
            New-Object -TypeName Object |
            Add-Member -MemberType NoteProperty -Name 'Name' -Value 'DummyShare' -PassThru |
            Add-Member -MemberType NoteProperty -Name 'ScopName' -Value '*' -PassThru |
            Add-Member -MemberType NoteProperty -Name 'AccountName' -Value "$($env:COMPUTERNAME)\User1" -PassThru |
            Add-Member -MemberType NoteProperty -Name 'AccessControlType' -Value 'Allow' -PassThru |
            Add-Member -MemberType NoteProperty -Name 'AccessRight' -Value 'Full' -PassThru
            ),
            (
            New-Object -TypeName Object |
            Add-Member -MemberType NoteProperty -Name 'Name' -Value 'DummyShare' -PassThru |
            Add-Member -MemberType NoteProperty -Name 'ScopName' -Value '*' -PassThru |
            Add-Member -MemberType NoteProperty -Name 'AccountName' -Value "$($env:COMPUTERNAME)\User2" -PassThru |
            Add-Member -MemberType NoteProperty -Name 'AccessControlType' -Value 'Allow' -PassThru |
            Add-Member -MemberType NoteProperty -Name 'AccessRight' -Value 'Change' -PassThru
            ),
            (
            New-Object -TypeName Object |
            Add-Member -MemberType NoteProperty -Name 'Name' -Value 'DummyShare' -PassThru |
            Add-Member -MemberType NoteProperty -Name 'ScopName' -Value '*' -PassThru |
            Add-Member -MemberType NoteProperty -Name 'AccountName' -Value "$($env:COMPUTERNAME)\User3" -PassThru |
            Add-Member -MemberType NoteProperty -Name 'AccessControlType' -Value 'Allow' -PassThru |
            Add-Member -MemberType NoteProperty -Name 'AccessRight' -Value 'Read' -PassThru
            )
        )

        Describe 'MSFT_xSmbShare\Get-TargetResource' -Tag 'Get' 
        {

            Context 'When the system is in the desired state' 
            {
                BeforeAll 
                {
                    # Per context-block initialization
                }

                # Mock the command to get the acl
                Mock Get-SmbShare -MockWith { return @($mockSmbShare)}
                Mock Get-SmbShareAccess -MockWith { return @($mockSmbShareAccess)}

                # Set testParameters
                $testParameters = @{Name = $mockSmbShare.Name}
                $testParamters += @{Path = $mockSmbShare.Path}

                # Call Get-TargetResource
                $result = Get-TargetResource @testParameters

                It 'Should mock call to Get-SmbShare and return membership' 
                {
                    $result.ChangeAccess | Should Be $mockSmbShareAccess.ChangeAccess
                    $result.ReadAccess | Should Be $mockSmbShareAccess.ReadAccess
                    $result.FullAccess | Should Be $mockSmbShareAccess.FullAccess
                    $result.NoAccess | Should Be $mockSmbShareAccess.NoAccess
                }

                It 'Should call the mock function Get-SmbShare'
                {
                    Assert-MockCalled Get-SmbShare -Exactly -Times 1 -ModuleName $script:DSCResourceName -Scope Context
                }

                It 'Should Call the mock function Get-SmbShareAccess'
                {
                    Assert-MockCalled Get-SmbShareAccess -Exactly -Times 1 -ModuleName $script:DSCResourceName -Scope Context
                }
            }
        }

        Describe 'MSFT_xSmbShare\Set-TargetResource' -Tag 'Set' 
        {
            Context 'When the system is not in the desired state' 
            {
                BeforeAll 
                {
                    # Per context-block initialization
                }

                # Set the testParameter collection
                $testParameters = @{ChangeAccess = $mockDefaultChangeAccess}
                $testParameters += @{ReadAccess = $mockDefaultReadAccess}
                $testParameters += @{FullAccess = $mockDefaultFullAccess}
                $testParameters += @{NoAccess = $mockDefaultNoAccess}
                $testParameters += @{Name = $mockSmbShare.Name}
                $testParameters += @{Path = $mockSmbShare.Path}
                $testParameters += @{Description = $mockSmbShare.Description}
                $testParameters += @{ConcurrentUserLimit = $mockSmbShare.ConcurrentUserLimit}
                $testParameters += @{EncryptData = $mockSmbShare.EncryptData}
                $testParameters += @{FolderEnumerationMode = $mockSmbShare.FolderEnumerationMode}
                $testParameters += @{Ensure = "Present"}

                # Set the script level parameters
                $script:ChangeAccess = $mockSmbShareAccess.Change
                $script:ReadAccess = $mockSmbShareAccess.Read
                $script:FullAccess = $mockSmbShareAccess.Full
                $script:NoAccess = @()

                # Set mock function calls
                Mock Get-SmbShare -MockWith { return @($mockSmbShare)}
                Mock Get-SmbShareAccess -MockWith { return @($mockSmbShareAccess)}
                Mock Set-SmbShare -MockWith { return $null}
                Mock Grant-SmbShareAccess -MockWith {
                    switch($AccessPermission)
                    {
                        "Change"
                        {
                            $script:ChangeAccess += $UserName
                        }
                        "Read"
                        {
                            $script:ReadAccess += $UserName
                        }
                        "Full"
                        {
                            $script:FullAccess += $UserName
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
                        }
                        "Read"
                        {
                            $script:ReadAccess = $script:ReadAccess | Where-Object {$_ -ne $UserName}
                        }
                        "Full"
                        {
                            $script:FullAccess = $script:FullAccess | Where-Object {$_ -ne $UserName}
                        }
                    }
                }
                Mock Unblock-SmbShareAccess -MockWith {
                    $script:NoAccess = $script:NoAccess | Where-Object {$_ -ne $UserName}
                }

                $result = Set-TargetResource @testParameters

                It 'Should alter permissions'
                {
                    $script:ChangeAccess | Should Be $mockChangeAccess
                    $script:ReadAccess | Should Be $mockReadAccess
                    $script:FullAccess | Should Be $mockFullAccess
                    $script:NoAccess | Should Be $mockNoAcess
                }
                
                It 'Should call the mock function Get-SmbShare'
                {
                    Assert-MockCalled Get-SmbShare -Exactly -Times 1 -ModuleName $script:DSCResourceName -Scope Context
                }

                It 'Should Call the mock function Get-SmbShareAccess'
                {
                    Assert-MockCalled Get-SmbShareAccess -Exactly -Times 1 -ModuleName $script:DSCResourceName -Scope Context
                }

                It 'Should call the mock function Set-SmbShare'
                {
                    Assert-MockCalled Set-SmbShare -Exactly -Times 1 -ModuleName $script:DSCResourceName -Scope Context
                }
            }
        }

        Describe 'MSFT_xSmbShare\Test-TargetResource' -Tag 'Test' 
        {
            Context 'When the system is in the desired state' 
            {

                # Set the testParameter collection
                $testParameters = @{ChangeAccess = $mockSmbShare.ChangeAccess}
                $testParameters += @{ReadAccess = $mockSmbShare.ReadAccess}
                $testParameters += @{FullAccess = $mockSmbShare.FullAccess}
                $testParameters += @{NoAccess = $mockSmbShare.NoAccess}
                $testParameters += @{Name = $mockSmbShare.Name}
                $testParameters += @{Path = $mockSmbShare.Path}
                $testParameters += @{Description = $mockSmbShare.Description}
                $testParameters += @{ConcurrentUserLimit = $mockSmbShare.ConcurrentUserLimit}
                $testParameters += @{EncryptData = $mockSmbShare.EncryptData}
                $testParameters += @{FolderEnumerationMode = $mockSmbShare.FolderEnumerationMode}
                $testParameters += @{Ensure = "Present"}


                BeforeAll 
                {
                    # Per context-block initialization
                }

                # Set mock function calls
                Mock Get-SmbShare -MockWith { return @($mockSmbShare)}
                Mock Get-SmbShareAccess -MockWith { return @($mockSmbShareAccess)}
                

                # Call the Test-TargetResource
                $result = Test-TargetResource @testParameters

                It 'Should return false' 
                {
                    # Result should be false
                    $result | Should be $false
                }
                
                It 'Should call the mock function Get-SmbShare'
                {
                    Assert-MockCalled Get-SmbShare -Exactly -Times 1 -ModuleName $script:DSCResourceName -Scope Context
                }

                It 'Should Call the mock function Get-SmbShareAccess'
                {
                    Assert-MockCalled Get-SmbShareAccess -Exactly -Times 1 -ModuleName $script:DSCResourceName -Scope Context
                }
            }

            Context 'When the system is not in the desired state' 
            {

                # Set the testParameter collection
                $testParameters = @{ChangeAccess = $mockDefaultChangeAccess}
                $testParameters += @{ReadAccess = $mockDefaultReadAccess}
                $testParameters += @{FullAccess = $mockDefaultFullAccess}
                $testParameters += @{NoAccess = $mockDefaultNoAccess}
                $testParameters += @{Name = $mockSmbShare.Name}
                $testParameters += @{Path = $mockSmbShare.Path}
                $testParameters += @{Description = $mockSmbShare.Description}
                $testParameters += @{ConcurrentUserLimit = $mockSmbShare.ConcurrentUserLimit}
                $testParameters += @{EncryptData = $mockSmbShare.EncryptData}
                $testParameters += @{FolderEnumerationMode = $mockSmbShare.FolderEnumerationMode}
                $testParameters += @{Ensure = "Present"}


                $result = Test-TargetResource @testParameters


                It 'Should return true' 
                {

                    # Result should be true
                    $result | Should be $true
                }
                
                It 'Should call the mock function Get-SmbShare'
                {
                    Assert-MockCalled Get-SmbShare -Exactly -Times 1 -ModuleName $script:DSCResourceName -Scope Context
                }

                It 'Should Call the mock function Get-SmbShareAccess'
                {
                    Assert-MockCalled Get-SmbShareAccess -Exactly -Times 1 -ModuleName $script:DSCResourceName -Scope Context
                }
            }
        }
    }
}
finally
{
    Invoke-TestCleanup
}