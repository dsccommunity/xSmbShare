function Get-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [parameter(Mandatory = $true)]
        [System.String]
        $Name,

        [parameter(Mandatory = $true)]
        [System.String]
        $Path
    )

    $smbShare = Get-SmbShare -Name $Name -ErrorAction SilentlyContinue
    $changeAccess = @()
    $readAccess = @()
    $fullAccess = @()
    $noAccess = @()
    if ($smbShare -ne $null)
    {
        $smbShareAccess = Get-SmbShareAccess -Name $Name
        $smbShareAccess | ForEach-Object  {
            $access = $_;
            if ($access.AccessRight -eq 'Change' -and $access.AccessControlType -eq 'Allow')
            {
                $changeAccess += $access.AccountName
            }
            elseif ($access.AccessRight -eq 'Read' -and $access.AccessControlType -eq 'Allow')
            {
                $readAccess += $access.AccountName
            }
            elseif ($access.AccessRight -eq 'Full' -and $access.AccessControlType -eq 'Allow')
            {
                $fullAccess += $access.AccountName
            }
            elseif ($access.AccessRight -eq 'Full' -and $access.AccessControlType -eq 'Deny')
            {
                $noAccess += $access.AccountName
            }
        }
    }
    else
    {
        Write-Verbose "Share with name $Name does not exist"
    }

    $returnValue = @{
        Name                  = $smbShare.Name
        Path                  = $smbShare.Path
        Description           = $smbShare.Description
        ConcurrentUserLimit   = $smbShare.ConcurrentUserLimit
        EncryptData           = $smbShare.EncryptData
        FolderEnumerationMode = $smbShare.FolderEnumerationMode
        CachingMode           = $smbShare.CachingMode
        ShareState            = $smbShare.ShareState
        ShareType             = $smbShare.ShareType
        ShadowCopy            = $smbShare.ShadowCopy
        Special               = $smbShare.Special
        ChangeAccess          = $changeAccess
        ReadAccess            = $readAccess
        FullAccess            = $fullAccess
        NoAccess              = $noAccess
        Ensure                = if($smbShare) {"Present"} else {"Absent"}
    }

    $returnValue
}

function Set-AccessPermission
{
    [CmdletBinding()]
    Param
    (
        $ShareName,

        [string[]]
        $UserName,

        [string]
        [ValidateSet("Change","Full","Read","No")]
        $AccessPermission
    )
    $formattedString = '{0}{1}' -f $AccessPermission,"Access"
    Write-Verbose -Message "Setting $formattedString for $UserName"

    if ($AccessPermission -eq "Change" -or $AccessPermission -eq "Read" -or $AccessPermission -eq "Full")
    {
        Grant-SmbShareAccess -Name $Name -AccountName $UserName -AccessRight $AccessPermission -Force
    }
    else
    {
        Block-SmbShareAccess -Name $Name -AccountName $userName -Force
    }
}

Function Set-BoundParameters
{
    # Define parameters
    Param
    (
        $BoundParameters
    )

    # Check for null access before passing to New-SmbShare
    if (($BoundParameters.ContainsKey("ChangeAccess")) -and ([string]::IsNullOrEmpty($BoundParameters["ChangeAccess"])))
    {
        Write-Verbose "Parameter ChangeAccess is null or empty, removing from collection."
        # Remove the parameter
        $BoundParameters.Remove("ChangeAccess")
    }

    if (($BoundParameters.ContainsKey("ReadAccess")) -and ([string]::IsNullOrEmpty($BoundParameters["ReadAccess"])))
    {
        Write-Verbose "Paramater ReadAccess is null or empty, removing from collection."
        # Remove the parameter
        $BoundParameters.Remove("ReadAccess")
    }

    if (($BoundParameters.ContainsKey("FullAccess")) -and ([string]::IsNullOrEmpty($BoundParameters["FullAccess"])))
    {
        Write-Verbose "Parameter FullAccess is null or empty, removing from collection."
        # Remove the parameter
        $BoundParameters.Remove("FullAccess")
    }

    if (($BoundParameters.ContainsKey("NoAccess")) -and ([string]::IsNullOrEmpty($BoundParameters["NoAccess"])))
    {
        Write-Verbose "Parameter NoAccess is null or empty, removing from collection."
        # Remove the parameter
        $BoundParameters.Remove("NoAccess")
    }

    # Return the parameter collection
    return $BoundParameters
}

function Remove-AccessPermission
{
    [CmdletBinding()]
    Param
    (
        $ShareName,

        [string[]]
        $UserName,

        [string]
        [ValidateSet("Change","Full","Read","No")]
        $AccessPermission
    )
    $formattedString = '{0}{1}' -f $AccessPermission,"Access"
    Write-Debug -Message "Removing $formattedString for $UserName"

    if ($AccessPermission -eq "Change" -or $AccessPermission -eq "Read" -or $AccessPermission -eq "Full")
    {
        Revoke-SmbShareAccess -Name $Name -AccountName $UserName -Force

}
    else
    {
        UnBlock-SmbShareAccess -Name $Name -AccountName $userName -Force
    }
}

function Set-TargetResource
{
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory = $true)]
        [System.String]
        $Name,

        [parameter(Mandatory = $true)]
        [System.String]
        $Path,

        [System.String]
        $Description,

        [System.String[]]
        $ChangeAccess,

        [System.UInt32]
        $ConcurrentUserLimit,

        [System.Boolean]
        $EncryptData,

        [ValidateSet("AccessBased","Unrestricted")]
        [System.String]
        $FolderEnumerationMode,

        [ValidateSet("None","Manual","Programs","Documents","BranchCache")]
        [System.String]
        $CachingMode,

        [System.String[]]
        $FullAccess,

        [System.String[]]
        $NoAccess,

        [System.String[]]
        $ReadAccess,

        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure = 'Present'
    )

    $PSBoundParameters.Remove("Debug")

    $shareExists = $false
    $smbShare = Get-SmbShare -Name $Name -ErrorAction SilentlyContinue
    if($smbShare -ne $null)
    {
        Write-Verbose -Message "Share with name $Name exists"
        $shareExists = $true
    }
    if ($Ensure -eq "Present")
    {
        if ($shareExists -eq $false)
        {
            $PSBoundParameters.Remove("Ensure")
            Write-Verbose "Creating share $Name to ensure it is Present"

            # Alter bound parameters
            $newShareParameters = Set-BoundParameters -BoundParameters $PSBoundParameters

            # Pass the parameter collection to New-SmbShare
            New-SmbShare @newShareParameters
        }
        else
        {
            # Need to call either Set-SmbShare or *ShareAccess cmdlets
            if ($PSBoundParameters.ContainsKey("ChangeAccess"))
            {
                $changeAccessValue = $PSBoundParameters["ChangeAccess"]
                $PSBoundParameters.Remove("ChangeAccess")
            }
            if ($PSBoundParameters.ContainsKey("ReadAccess"))
            {
                $readAccessValue = $PSBoundParameters["ReadAccess"]
                $PSBoundParameters.Remove("ReadAccess")
            }
            if ($PSBoundParameters.ContainsKey("FullAccess"))
            {
                $fullAccessValue = $PSBoundParameters["FullAccess"]
                $PSBoundParameters.Remove("FullAccess")
            }
            if ($PSBoundParameters.ContainsKey("NoAccess"))
            {
                $noAccessValue = $PSBoundParameters["NoAccess"]
                $PSBoundParameters.Remove("NoAccess")
            }

            # Use Set-SmbShare for performing operations other than changing access
            $PSBoundParameters.Remove("Ensure")
            $PSBoundParameters.Remove("Path")
            Set-SmbShare @PSBoundParameters -Force

            # Use *SmbShareAccess cmdlets to change access
            $smbShareAccessValues = Get-SmbShareAccess -Name $Name

            # Remove Change permissions
            $smbShareAccessValues | Where-Object {$_.AccessControlType  -eq 'Allow' -and $_.AccessRight -eq 'Change'} `
                                    | ForEach-Object {
                                        Remove-AccessPermission -ShareName $Name -UserName $_.AccountName -AccessPermission Change
                                        }

            if ($ChangeAccess -ne $null)
            {
                # Add change permissions
                $changeAccessValue | ForEach-Object {
                                        Set-AccessPermission -ShareName $Name -AccessPermission "Change" -Username $_
                                       }
            }

            $smbShareAccessValues = Get-SmbShareAccess -Name $Name

            # Remove read access
            $smbShareAccessValues | Where-Object {$_.AccessControlType  -eq 'Allow' -and $_.AccessRight -eq 'Read'} `
                                    | ForEach-Object {
                                        Remove-AccessPermission -ShareName $Name -UserName $_.AccountName -AccessPermission Read
                                        }

            if ($ReadAccess -ne $null)
            {
                # Add read access
                $readAccessValue | ForEach-Object {
                                       Set-AccessPermission -ShareName $Name -AccessPermission "Read" -Username $_
                                     }
            }


            $smbShareAccessValues = Get-SmbShareAccess -Name $Name

            # Remove full access
            $smbShareAccessValues | Where-Object {$_.AccessControlType  -eq 'Allow' -and $_.AccessRight -eq 'Full'} `
                                    | ForEach-Object {
                                        Remove-AccessPermission -ShareName $Name -UserName $_.AccountName -AccessPermission Full
                                        }


            if ($FullAccess -ne $null)
            {

                # Add full access
                $fullAccessValue | ForEach-Object {
                                        Set-AccessPermission -ShareName $Name -AccessPermission "Full" -Username $_
                                     }
            }

            $smbShareAccessValues = Get-SmbShareAccess -Name $Name

            # Remove explicit deny
            $smbShareAccessValues | Where-Object {$_.AccessControlType  -eq 'Deny'} `
                                    | ForEach-Object {
                                        Remove-AccessPermission -ShareName $Name -UserName $_.AccountName -AccessPermission No
                                        }


            if ($NoAccess -ne $null)
            {
                # Add explicit deny
                $noAccessValue | ForEach-Object {
                                      Set-AccessPermission -ShareName $Name -AccessPermission "No" -Username $_
                                   }
            }
        }
    }
    else
    {
        Write-Verbose "Removing share $Name to ensure it is Absent"
        Remove-SmbShare -name $Name -Force
    }
}

function Test-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [parameter(Mandatory = $true)]
        [System.String]
        $Name,

        [parameter(Mandatory = $true)]
        [System.String]
        $Path,

        [System.String]
        $Description,

        [System.String[]]
        $ChangeAccess,

        [System.UInt32]
        $ConcurrentUserLimit,

        [System.Boolean]
        $EncryptData,

        [ValidateSet("AccessBased","Unrestricted")]
        [System.String]
        $FolderEnumerationMode,

        [ValidateSet("None","Manual","Programs","Documents","BranchCache")]
        [System.String]
        $CachingMode,

        [System.String[]]
        $FullAccess,

        [System.String[]]
        $NoAccess,

        [System.String[]]
        $ReadAccess,

        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure = 'Present'
    )

    # Alter the bound parameters, removing anything that is null or emtpy
    $alteredBoundParameters = Set-BoundParameters -boundparameters $PSBoundParameters

    $testResult = $false;
    $share = Get-TargetResource -Name $Name -Path $Path -ErrorAction SilentlyContinue -ErrorVariable ev
    $differences = @()
    if ($Ensure -ne "Absent")
    {
        if ($share.Ensure -eq "Absent")
        {
            $testResult = $false
        }
        elseif ($share.Ensure -eq "Present")
        {
            $Params = 'Name', 'Path', 'Description', 'ChangeAccess', 'ConcurrentUserLimit', 'EncryptData', 'FolderEnumerationMode', 'CachingMode', 'FullAccess', 'NoAccess', 'ReadAccess', 'Ensure'

            # Get all matching parameters from alteredBoundParameters that are in Params
            $matchingParameters = $alteredBoundParameters.Keys.Where({($_ -in $Params)})

            if ($null -ne $matchingParameters)
            {
                foreach ($matchingParameter in $matchingParameters)
                {
                    $differences += Compare-Object -ReferenceObject $alteredBoundParameters[$matchingParameter] -DifferenceObject $share.$matchingParameter #; $differences
                }

                # Check to see if there is anything in $differences
                if (($null -ne $differences) -and ($differences.Length -gt 0))
                {
                    $differences | ForEach-Object {Write-Verbose -Message "$_"}
                    $testResult = $false
                }
                else
                {
                    $testResult = $true
                }
            }
            else
            {
                $testResult = $true
            }
        }
    }
    else
    {
        if ($share.Ensure -eq "Absent")
        {
            $testResult = $true
        }
        else
        {
            $testResult = $false
        }
    }

    $testResult
}

Export-ModuleMember -Function *-TargetResource
