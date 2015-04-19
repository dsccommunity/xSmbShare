function Test-Permissions
{
   
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

		[ValidateSet('AccessBased','Unrestricted')]
		[System.String]
		$FolderEnumerationMode,

		[System.String[]]
		$FullAccess,

		[System.String[]]
		$NoAccess,

		[System.String[]]
		$ReadAccess,

		[ValidateSet('Present','Absent')]
		[System.String]
		$Ensure = 'Present'
	)

   
   
    $testResult = $false

    $PSBound = $PSBoundParameters
    $PSBound.Remove('Debug') | Out-Null
    $PSBound.Remove('Verbose') | Out-Null
    $PSBound.Remove('DependsOn') | Out-Null

## getting current permissions assigned to the shares 

$smbShare = Get-SmbShare -Name $Name -ErrorAction SilentlyContinue

    $CurrentchangeAccess = @()
    $CurrentreadAccess = @()
    $CurrentfullAccess = @()
    $CurrentnoAccess = @()
    if ($smbShare -ne $null)
    {
        $smbShareAccess = Get-SmbShareAccess -Name $Name
        $smbShareAccess | %  {
            $access = $_;
            if ($access.AccessRight -eq 'Change' -and $access.AccessControlType -eq 'Allow')
            {
                $CurrentchangeAccess += $access.AccountName
            }
            elseif ($access.AccessRight -eq 'Read' -and $access.AccessControlType -eq 'Allow')
            {
                $CurrentreadAccess += $access.AccountName
            }            
            elseif ($access.AccessRight -eq 'Full' -and $access.AccessControlType -eq 'Allow')
            {
                $CurrentfullAccess += $access.AccountName
            }
            elseif ($access.AccessRight -eq 'Full' -and $access.AccessControlType -eq 'Deny')
            {
                $CurrentnoAccess += $access.AccountName
            }
        }
    }
    else
    {
        Write-Verbose "Share with name $Name does not exist"
        
    } 


$CurrentConfiguration = @{
		Name = $smbShare.Name
		Path = $smbShare.Path
        Description = $smbShare.Description
		ConcurrentUserLimit = $smbShare.ConcurrentUserLimit
		EncryptData = $smbShare.EncryptData
		FolderEnumerationMode = $smbShare.FolderEnumerationMode	    		
        ChangeAccess = $CurrentchangeAccess
        ReadAccess = $CurrentreadAccess
        FullAccess = $CurrentfullAccess
        NoAccess = $CurrentnoAccess     
        Ensure = if($smbShare) {'Present'} else {'Absent'}
	}


## This is needed for second testing of other paramaters its the same as $CurrentConfiguration

$CurrentConfiguration2 = @{
		Name = $smbShare.Name
		Path = $smbShare.Path
        Description = $smbShare.Description
		ConcurrentUserLimit = $smbShare.ConcurrentUserLimit
		EncryptData = $smbShare.EncryptData
		FolderEnumerationMode = $smbShare.FolderEnumerationMode	    		
        ChangeAccess = $CurrentchangeAccess
        ReadAccess = $CurrentreadAccess
        FullAccess = $CurrentfullAccess
        NoAccess = $CurrentnoAccess     
        Ensure = if($smbShare) {'Present'} else {'Absent'}
	}


$SpecifiedParameters = @{
		Name = $Name
		Path = $Path
        Description = $Description
		ChangeAccess = $ChangeAccess
		ConcurrentUserLimit = $ConcurrentUserLimit
		EncryptData = $EncryptData    		
        FolderEnumerationMode = $FolderEnumerationMode
        FullAccess = $FullAccess
        NoAccess = $NoAccess
        ReadAccess = $ReadAccess    
        Ensure = $Ensure
	}


## Counting Numbers for loop  FullAccess 

if ($CurrentConfiguration.fullaccess.Count -gt $PSBound.fullaccess.count)
{
$numberfullaccess = $CurrentConfiguration.fullaccess.Count

}else {


$numberfullaccess = $PSBound.fullaccess.count


}

## Counting Numbers for loop ReadAccess

if ($CurrentConfiguration.readaccess.Count -gt $PSBound.readaccess.count)
{
$numberreadaccess = $CurrentConfiguration.readaccess.Count

}else {


$numberreadaccess = $PSBound.readaccess.count


}

## Counting Numbers for loop ChangeAccess

if ($CurrentConfiguration.ChangeAccess.Count -gt $PSBound.ChangeAccess.count)
{
$numberChangeAccess = $CurrentConfiguration.ChangeAccess.Count

}else {


$numberChangeAccess = $PSBound.ChangeAccess.count


}

## Counting Numbers for loop NOAccess

if ($CurrentConfiguration.noaccess.Count -gt $PSBound.noaccess.count)
{
$numbernoaccess = $CurrentConfiguration.noaccess.Count

}else {


$numbernoaccess = $PSBound.noaccess.count


}

	 

  $RemovingUserPermission = @{}  
  $TestingcorrectperrmissionAndparameters = @()
  $AddingUserPermission = @{}
 


##Testing if the user has to be Removed from the share and Testing correct permission state

If   ($PSBound.ContainsKey('noaccess')){

    
    for ($i = 0; $i -lt $numbernoaccess; $i++)
    { 

     $result =  ($PSBound.noaccess   -contains    $CurrentConfiguration.NoAccess[$i]).ToString()  

      $user =  $CurrentConfiguration.NoAccess[$i]
      
      if($user){

## If the user should not have permission we will add him to this  Variable 
     
     $TestingcorrectperrmissionAndparameters += $result

     $RemovingUserPermission.add($user,$result)
      

      }
      
     }
        
    }#end IF 

If   ($PSBound.ContainsKey('fullaccess')){

     for ($i = 0; $i -lt $numberfullaccess ; $i++)
    { 

     $result =  ($PSBound.fullaccess  -contains    $CurrentConfiguration.fullaccess[$i]).ToString()  

     $user = $CurrentConfiguration.fullaccess[$i]

     if($user){

     $TestingcorrectperrmissionAndparameters += $result
     
## If the user should not have permission we will add him to this  Variable 


     $RemovingUserPermission.add($user,$result)
      
      }

        
    }




}#end IF

If   ($PSBound.ContainsKey('readaccess')){

     for ($i = 0; $i -lt $numberreadaccess; $i++)
    { 

     $result =  ($PSBound.readaccess   -contains    $CurrentConfiguration.readaccess[$i]).ToString() 

     $user = $CurrentConfiguration.readaccess[$i]


      if($user){

## If the user should not have permission we will add him to this  Variable 
        $TestingcorrectperrmissionAndparameters += $result

     $RemovingUserPermission.add($user,$result)
      
      }

     }   
    
    } #end IF

If   ($PSBound.ContainsKey('ChangeAccess')){

     for ($i = 0; $i -lt $numberChangeAccess; $i++)
    { 

     $result =  ($PSBound.ChangeAccess   -contains    $CurrentConfiguration.ChangeAccess[$i]).ToString() 

     $user = $CurrentConfiguration.ChangeAccess[$i]

     if($user){

     $TestingcorrectperrmissionAndparameters += $result

## If the user should not have permission we will add him to this  Variable 


    $RemovingUserPermission.add($user,$result )
      
      }

     }   
    
    } #end IF



##Testing if the user has to be Added to the share and Testing correct permission State

If   ($PSBound.ContainsKey('noaccess')){

    
    for ($i = 0; $i -lt $numbernoaccess; $i++)
    { 
        
      $ErrorActionPreference = "SilentlyContinue"

      $result =  ($CurrentConfiguration.noaccess   -contains $PSBound.NoAccess[$i]).ToString()  

      $user =  $PSBound.NoAccess[$i] 
      
      if($user){

## If the User should should have permission we will  add him to this Variable

      $TestingcorrectperrmissionAndparameters += $result
      $addeduser = $PSBound.NoAccess
      $AddingUserPermission.add($addeduser[$i],$result)

      $ErrorActionPreference = "Continue"
      
      $user=$null
      
      }
      
     }
        
    }#end IF 

If   ($PSBound.ContainsKey('readaccess')){

     for ($i = 0; $i -lt $numberreadaccess; $i++)
    { 
      $ErrorActionPreference = "SilentlyContinue"

     $result =  ($CurrentConfiguration.readaccess   -contains    $PSBound.readaccess[$i]).ToString() 

     $user = $PSBound.readaccess[$i]
     

      if($user){


## If the User should should have permission we will  add him to this Variable

      $TestingcorrectperrmissionAndparameters += $result

      $addeduser = $PSBound.readaccess

      $ErrorActionPreference = "SilentlyContinue"
      $AddingUserPermission.add($addeduser[$i],$result)

      $user=$null

      $ErrorActionPreference = "Continue"
      } 

     }   
    
    } #end IF

If   ($PSBound.ContainsKey('fullaccess')){

     for ($i = 0; $i -lt $numberfullaccess ; $i++)
    { 
     $ErrorActionPreference = "SilentlyContinue"

     $result =  ($CurrentConfiguration.fullaccess  -contains    $PSBound.fullaccess[$i] ).ToString()  

     $user = $PSBound.fullaccess[$i]
     


     if($user){


## If the User should should have permission we will  add him to this Variable

     $TestingcorrectperrmissionAndparameters += $result

      $addeduser = $PSBound.fullaccess
      $AddingUserPermission.add($addeduser[$i],$result)

      $ErrorActionPreference = "Continue"
      $user=$null

      }

        
    }




}#end IF

If   ($PSBound.ContainsKey('ChangeAccess')){

     for ($i = 0; $i -lt $numberChangeAccess; $i++)
    { 
     $ErrorActionPreference = "SilentlyContinue"
     $result =  ($CurrentConfiguration.ChangeAccess   -contains   $PSBound.ChangeAccess[$i]).ToString() 

     $user = $PSBound.ChangeAccess[$i]

 

     if($user){

      
## we are adding user to Variable      
      $TestingcorrectperrmissionAndparameters += $result

      $addeduser = $PSBound.ChangeAccess
  
      $AddingUserPermission.add($addeduser[$i],$result)
      $ErrorActionPreference = "Continue"
      $user=$null
      `
      } 

     }   
    
    } #end IF
 
$AddingUserPermissiontoObject = @{}

## Creating Object for with user and permission that needs to be assigned 

$usersadd = ($AddingUserPermission.GetEnumerator() | Where-Object { $_.value -eq "False"}).name 

foreach ( $user in $usersadd){


if ($PSBound.ReadAccess -contains $user  )

{

$AddingUserPermissiontoObject.add($user ,"Read" )


}

if ($PSBound.noaccess -contains $user  )

{

$AddingUserPermissiontoObject.add($user ,"no" )


}

if ($PSBound.fullaccess -contains $user  )

{

$AddingUserPermissiontoObject.add($user ,"full" )


}


if ($PSBound.ChangeAccess -contains $user  )

{

$AddingUserPermissiontoObject.add($user ,"Change" )


}


}


## Now we assigning Global Variable which we can use in Set-TargetResources

$global:AddingUsersandPermissions = $AddingUserPermissiontoObject.GetEnumerator() | Where-Object { $_.value }






## Now we are testing if we need to remove some permission that we are unable to test above 

## Comparing Assigned parameters with Current configuration and removing unnecessary parameters


$ListofAssignedParameters = $PSBound.Keys.Split('"') 

## We removing all parameters expect permission so then we can see if there is something we need to add . 

foreach ($param in $ListofAssignedParameters) {

$CurrentConfiguration.Remove($param)

}


if ($CurrentConfiguration.ContainsKey('EncryptData')){

$CurrentConfiguration.Remove('EncryptData')
}

if ($CurrentConfiguration.ContainsKey('ConcurrentUserLimit')){

$CurrentConfiguration.Remove('ConcurrentUserLimit')
}

$ListofCurrentParam = $CurrentConfiguration.keys -join ' ' -split ' '

## Aswell comparing if there is extra parameters and assign it to $TestingcorrectperrmissionAndparameters

foreach ($listparam in $ListofCurrentParam) {  if($CurrentConfiguration[$listparam]){

$trial =     $CurrentConfiguration.GetEnumerator() |Where-Object { $_.name -eq $listparam } | select value -ExpandProperty value
$RemovingUserPermission.add($trial,"False")

$TestingcorrectperrmissionAndparameters += "False"

}else{


$TestingcorrectperrmissionAndparameters += "True"

} }



  

## Creating Object for with user and Permission that need to be Removed

$RemovingPermissiontoObject = @{}

$usersremove = ($RemovingUserPermission.GetEnumerator() | Where-Object { $_.value -eq "False"}).name

    foreach ( $user in $usersremove){


if ($CurrentConfiguration2.ReadAccess -contains $user  )

{

$RemovingPermissiontoObject.add($user ,"Read" )


}

if ($CurrentConfiguration2.noaccess -contains $user  )

{

$RemovingPermissiontoObject.add($user ,"no" )


}

if ($CurrentConfiguration2.fullaccess -contains $user  )

{

$RemovingPermissiontoObject.add($user ,"full" )


}


if ($CurrentConfiguration2.ChangeAccess -contains $user  )

{

$RemovingPermissiontoObject.add($user ,"Change" )


}


}

## Now we assigning Global Variable which we can use in Set-TargetResources

$global:RemovingUsersandPermissions = $RemovingPermissiontoObject.GetEnumerator() | Where-Object { $_.value }





## Removing Keys from PSBoundParameters

 $PSBound.Remove('fullaccess') | Out-Null
 $PSBound.Remove('readaccess') | Out-Null
 $PSBound.Remove('noaccess') | Out-Null
 $PSBound.Remove('ChangeAccess') | Out-Null



## Testing the rest of  parameters (not Permissions) if they are correct 

$PSBoundParameter = $PSBound.Keys.Split('"')


$OtherParamResult  = @()


for ($i = 0; $i -lt $PSBoundParameter.Count ; $i++)
{ 
 
 $test1 = ($PSBound[$PSBoundParameter[$i]]-join ' ').ToString()
 $test2  = ($CurrentConfiguration2[$PSBoundParameter[$i]]-join ' ' ).ToString()

 $result = ($test1 -eq $test2 ).ToString()
 
 
 $OtherParamResult += $result
 
    
}



## This result Specifie if there is any changes  from assigned and current configuration
## If there is false in the list then there is something wrong with configuration 

$global:finalresult =$OtherParamResult  + $TestingcorrectperrmissionAndparameters


}

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
        $smbShareAccess | %  {
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
		Name = $smbShare.Name
		Path = $smbShare.Path
        Description = $smbShare.Description
		ConcurrentUserLimit = $smbShare.ConcurrentUserLimit
		EncryptData = $smbShare.EncryptData
		FolderEnumerationMode = $smbShare.FolderEnumerationMode	    		
        ShareState = $smbShare.ShareState
        ShareType = $smbShare.ShareType
        ShadowCopy = $smbShare.ShadowCopy
        Special = $smbShare.Special
        ChangeAccess = $changeAccess
        ReadAccess = $readAccess
        FullAccess = $fullAccess
        NoAccess = $noAccess     
        Ensure = if($smbShare) {'Present'} else {'Absent'}
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
        [ValidateSet('Change','Full','Read','No')]
        $AccessPermission
    )
    $formattedString = '{0}{1}' -f $AccessPermission,'Access'
    Write-Verbose -Message "Setting $formattedString for $UserName"

    if ($AccessPermission -eq 'Change' -or $AccessPermission -eq 'Read' -or $AccessPermission -eq 'Full')
    {
        Grant-SmbShareAccess -Name $Name -AccountName $UserName -AccessRight $AccessPermission -Force
    }
    else
    {
        Block-SmbShareAccess -Name $Name -AccountName $userName -Force
    }
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
        [ValidateSet('Change','Full','Read','No')]
        $AccessPermission
    )
    $formattedString = '{0}{1}' -f $AccessPermission,'Access'
    Write-Verbose -Message "Removing $formattedString for $UserName"

   

    if ($AccessPermission -eq 'Change' -or $AccessPermission -eq 'Read' -or $AccessPermission -eq 'Full')
    {
       
        
        Revoke-SmbShareAccess -Name $Name -AccountName $UserName   -Force
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

		[ValidateSet('AccessBased','Unrestricted')]
		[System.String]
		$FolderEnumerationMode="Unrestricted",

		[System.String[]]
		$FullAccess,

		[System.String[]]
		$NoAccess,

		[System.String[]]
		$ReadAccess,

		[ValidateSet('Present','Absent')]
		[System.String]
		$Ensure
	)

    $psbound  = $psboundparameters
    $psbound.Remove('Debug') 
   
    
  
   
	$shareExists = $false
    $smbShare = Get-SmbShare -Name $Name -ErrorAction SilentlyContinue

    if($smbShare -ne $null)
    {
        Write-Verbose -Message "Share with name $Name exists"
        $shareExists = $true
    }
    
    if ($Ensure -eq 'Present')
    {
    
        
        if ($shareExists -eq $false)
        {
            
                
 



            $psbound.Remove('Ensure')
            Write-Verbose "Creating share $Name to ensure it is Present"
            New-SmbShare -Name $name -Path $path


             #Assigning Permissions

            if ($psbound.ContainsKey('ChangeAccess'))
            {
                $changeAccessValue = $psbound['ChangeAccess']
                $psbound.Remove('ChangeAccess')
            }
            if ($psbound.ContainsKey('ReadAccess'))
            {
                $readAccessValue = $psbound['ReadAccess']
                $psbound.Remove('ReadAccess')
            }
            if ($psbound.ContainsKey('FullAccess'))
            {
                $fullAccessValue = $psbound['FullAccess']
                $psbound.Remove('FullAccess')
            }
            if ($psbound.ContainsKey('NoAccess'))
            {
                $noAccessValue = $psbound['NoAccess']
                $psbound.Remove('NoAccess')
            }
            
            # Use Set-SmbShare for performing operations other than changing access
            $psbound.Remove('Ensure')
            $psbound.Remove('Path')
            Set-SmbShare @psbound -Force
            
            # Use *SmbShareAccess cmdlets to change access
            $smbshareAccessValues = Get-SmbShareAccess -Name $Name
            if ($ChangeAccess -ne $null)
            {
                # Blow off whatever is in there and replace it with this list
                $smbshareAccessValues | ? {$_.AccessControlType  -eq 'Allow' -and $_.AccessRight -eq 'Change'} `
                                      | % {
                                            Remove-AccessPermission -ShareName $Name -UserName $_.AccountName -AccessPermission Change
                                          }
                                  
                $changeAccessValue | % {
                                        Set-AccessPermission -ShareName $Name -AccessPermission 'Change' -Username $_
                                       }
            }
            $smbshareAccessValues = Get-SmbShareAccess -Name $Name
            if ($ReadAccess -ne $null)
            {
                # Blow off whatever is in there and replace it with this list
                $smbshareAccessValues | ? {$_.AccessControlType  -eq 'Allow' -and $_.AccessRight -eq 'Read'} `
                                      | % {
                                            Remove-AccessPermission -ShareName $Name -UserName $_.AccountName -AccessPermission Read
                                          }

                $readAccessValue | % {
                                       Set-AccessPermission -ShareName $Name -AccessPermission 'Read' -Username $_                        
                                     }
            }
            $smbshareAccessValues = Get-SmbShareAccess -Name $Name
            if ($FullAccess -ne $null)
            {
                # Blow off whatever is in there and replace it with this list
                $smbshareAccessValues | ? {$_.AccessControlType  -eq 'Allow' -and $_.AccessRight -eq 'Full'} `
                                      | % {
                                            Remove-AccessPermission -ShareName $Name -UserName $_.AccountName -AccessPermission Full
                                          }

                $fullAccessValue | % {
                                        Set-AccessPermission -ShareName $Name -AccessPermission 'Full' -Username $_                        
                                     }
            }
            $smbshareAccessValues = Get-SmbShareAccess -Name $Name
            if ($NoAccess -ne $null)
            {
                # Blow off whatever is in there and replace it with this list
                $smbshareAccessValues | ? {$_.AccessControlType  -eq 'Deny'} `
                                      | % {
                                            Remove-AccessPermission -ShareName $Name -UserName $_.AccountName -AccessPermission No
                                          }
                $noAccessValue | % {
                                      Set-AccessPermission -ShareName $Name -AccessPermission 'No' -Username $_
                                   }


        }
        }else
        {


  

$specifedParam = @{


   Name = $Name
   Path = $Path
   ChangeAccess = $ChangeAccess
   ConcurrentUserLimit = $ConcurrentUserLimit
   Description = $Description
   EncryptData =$EncryptData
   Ensure = $Ensure
   FolderEnumerationMode=$FolderEnumerationMode
   FullAccess=$FullAccess
   NoAccess=$NoAccess
   ReadAccess=$ReadAccess


}

Test-Permissions @specifedParam



            # Need to call either Set-SmbShare or *ShareAccess cmdlets
            if ($psbound.ContainsKey('ChangeAccess'))
            {
                $changeAccessValue =$psbound['ChangeAccess']
               $psbound.Remove('ChangeAccess')
            }
            if ($psbound.ContainsKey('ReadAccess'))
            {
                $readAccessValue =$psbound['ReadAccess']
               $psbound.Remove('ReadAccess')
            }
            if ($psbound.ContainsKey('FullAccess'))
            {
                $fullAccessValue =$psbound['FullAccess']
               $psbound.Remove('FullAccess')
            }
            if ($psbound.ContainsKey('NoAccess'))
            {
                $noAccessValue =$psbound['NoAccess']
               $psbound.Remove('NoAccess')
            }
            
            # Use Set-SmbShare for performing operations other than changing access
           $psbound.Remove('Ensure')
           $psbound.Remove('Path')
           Set-SmbShare @psbound -Force
            
       
        $smbshareAccessValues = Get-SmbShareAccess -Name $Name

  


        if($RemovingUsersandPermissions){


        ## Removin  users From Shares 

         
        foreach ($RemovingUsers in $RemovingUsersandPermissions){


       
         Remove-AccessPermission -ShareName $Name -UserName $RemovingUsers.name -AccessPermission $RemovingUsers.value }
    


        }
    
           
           ## Adding Permissions and users to Shares 


       foreach ($UserandPerm in $AddingUsersandPermissions){

                

            Set-AccessPermission -ShareName $Name -AccessPermission $UserandPerm.value -Username $UserandPerm.name
                     
                                                            }

      
        }
    }#finish Presnet
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

		[ValidateSet('AccessBased','Unrestricted')]
		[System.String]
		$FolderEnumerationMode="Unrestricted",

		[System.String[]]
		$FullAccess,

		[System.String[]]
		$NoAccess,

		[System.String[]]
		$ReadAccess,

		[ValidateSet('Present','Absent')]
		[System.String]
		$Ensure = 'Present'
	)
   

$Share = Get-SmbShare -Name $Name -ErrorAction SilentlyContinue



$specifedParam = @{


   Name = $Name
   Path = $Path
   ChangeAccess = $ChangeAccess
   ConcurrentUserLimit = $ConcurrentUserLimit
   Description = $Description
   EncryptData =$EncryptData
   Ensure = $Ensure
   FolderEnumerationMode=$FolderEnumerationMode
   FullAccess=$FullAccess
   NoAccess=$NoAccess
   ReadAccess=$ReadAccess


}

Test-permissions @specifedParam



Write-Verbose 'Testing perrmisions'

    if ($Ensure -eq 'Present')
    {
        if ($share -eq $null)
        {
            $testResult = $false
        }
        elseif ($share -ne $null -and $finalresult -contains 'false' )


        {

            Write-Verbose 'There is something wrong'

            $testResult = $false

        }


        else
        {
            Write-Verbose 'All good with Permissions and Share'

            $testResult = $true

        }
    }


    else
    {
        if ($share -eq $null)
        {
            Write-Verbose 'All GOOD'

            $testResult = $true
        }
        else
        {
             Write-Verbose 'Share Needs to be Removed'

            $testResult = $false
        }
    }

	$testResult
}



Export-ModuleMember -Function *-TargetResource



