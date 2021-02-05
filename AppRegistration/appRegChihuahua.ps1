#date:      29.01.2021
#author:    oh22information services GmbH
#version:   0.0.1 - dev

<#
This script should 
add an new app registration,
bind to the web app, 
set up web app auth settings,


#>

<#Prerequisites:
    -local admin privs to install needed modules
    -Azure AD admin with role/permission to create and edit app registration / enterprise app registrations
    -Azure Subscription / Resource group role to edit web app
#>

<#usage:

    1) 
#>

#parameter section
Param(
    [parameter(Mandatory=$false, HelpMessage="name of the resource group where the app is located")]
    [String]
    [ValidateNotNullOrEmpty()] 
    $resourceGroupName,

    [parameter(Mandatory=$false, HelpMessage="name of the desired app registration in AzureAD")]
    [String]
    [ValidateNotNullOrEmpty()]
    $appRegistrationName,

    [parameter(Mandatory=$false, HelpMessage="name of the web app in Azure")]
    [String]
    [ValidateNotNullOrEmpty()]
    $appName,
    
    [parameter(Mandatory=$false, HelpMessage="id of the subscription where the app is located")]
    [String]
    [ValidateNotNullOrEmpty()]
    $subscriptionID,

    [parameter(Mandatory=$false, HelpMessage="id of the AzureAD tenant where the app registration should be located")]
    [String]
    [ValidateNotNullOrEmpty()]
    $TenantID
) 

#function section
function fnLogin-Azure ($subscriptionID){

    Write-Host ("Please log in Azure") -ForegroundColor Green;
    #Login to Azure with subscription ID

    try {
        Login-AzAccount -SubscriptionId $subscriptionID | Out-Null;

    }catch{
        Write-Warning -Message "login issue" 
        #end script
        return 777;
    }       
    
}

function fnLogin-AzureWithOutSubscription (){

    Write-Host ("Please log in Azure") -ForegroundColor Green;
    #login without subscription ID

        try {
            Login-AzAccount | Out-Null;

        }catch{
            Write-Warning -Message "login issue" 
            #end script
            return 777;
        }
        if(fncheckFor-Error -eq 777){return 777;}
        #set desired suscription ID
        #$myAvailabeSubscriptions = @();
        [array]$myAvailabeSubscriptions = Get-AzSubscription;
        [bool]$myIsValid = $false;

        #if more than one ask for the desired one
        if($myAvailabeSubscriptions.count -gt 1){
            while($myIsValid -eq $false){
                        
                #user interaction to choose the subscription
                Write-Host ("More than one subscription found:") -ForegroundColor Green;
                for($i=0; $i -lt $myAvailabeSubscriptions.count; $i++){
                    Write-Host "NR:" $i "`t" $myAvailabeSubscriptions[$i].ID "`t" $myAvailabeSubscriptions[$i].Name ;
                }
                try{
                    [int]$myChoice = Read-Host -Prompt ("`nPlease enter the number(NR:) of the desired subscription") -ErrorAction Stop
                    #if(fncheckFor-Error -eq 777){return 777;}
                }catch{
                    #catch is needed if the input is not a integer value
                    $Error.Clear();
                }

                #check if input is valid
                if($myChoice -lt $myAvailabeSubscriptions.Count -and ($myChoice -match '^\d+$')){
                    #set bool to end while
                    $myIsValid = $true;

                    #set var
                    $subscriptionID = $myAvailabeSubscriptions[$myChoice].ID
                    
                    #set subscription context
                    Set-AzContext -SubscriptionId $subscriptionID | Out-Null;

                    #output
                    Write-Host ("thank you " + $myAvailabeSubscriptions[$myChoice].Name + " is set`n");
                }
                #input is not valid
                else{
                    #output 
                    Write-Warning "You did not provide a valid value as input, try again";
                }
            };
        }
        #only one
        else{
            #set var
            $subscriptionID = $myAvailabeSubscriptions[0].Id;
        }
        #return
        return $subscriptionID;
    
}

function fnLogin-AzureAD ($TenantID) {

    Write-Host ("Please log in Azure AD") -ForegroundColor Green;
    #Login zu Azure
    try {
        if($TenantID){
            Connect-AzureAD -TenantId $TenantID;
        }
        else{
            Connect-AzureAD;
        }
    }catch{
        Write-Warning -Message "login issue" 
        #end script
        return 777;
    }
}

function fnLogout-all(){
    Logout-AzAccount | Out-Null;
    Disconnect-AzureAD | Out-Null;
}

function fnCheckFor-Error(){
    if($Error){
        #output the error 
        Write-Host ($Error.exception) -ForegroundColor Red -BackgroundColor Black;
        Write-Host "some error occurs";
        #log out if possible
        fnLogout-all;
        #return  
        return 777;
    }
}

function fnSet-ResourceGroup($resourceGroupName){
        
    #check if resource group is reachable 
    Write-Host ("**try to find resource group**") -ForegroundColor Yellow;
    $resourceGroup = Get-AzResourceGroup -Name $resourceGroupName;
    if(fncheckFor-Error -eq 777){return 777;}
    Write-Host ("resource group `"{0}`" found" -f $resourceGroup.ResourceGroupName) -ForegroundColor Green;
    return $resourceGroup;
}

function fnSet-WebApp($resourceGroupName, $appName){
        
    #check if web app is reachable 
    Write-Host ("**try to find web app**") -ForegroundColor Yellow;
    $webApp = Get-AzWebApp -ResourceGroupName $resourceGroupName -Name $appName;
    if(fncheckFor-Error -eq 777){return 777;}
    Write-Host ("web app `"{0}`" found" -f $webApp.Name) -ForegroundColor Green;
    return $webApp;
}

function fnSet-AppRegistrationName($appRegistrationName){
    #set info for user interaction
    $title = "Select name for app registration";
    $message = "Do you want to use `"" + $appRegistrationName + "`" as name for the app registration?";  

    $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", `
        "Use the app name as name for the app registration."

    $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", `
        "Type in your desired name.(There is no check if the name will be valid)"

    $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)

    $result = $host.ui.PromptForChoice($title, $message, $options, 0)


    switch ($result)
        {
            0 {} #keep $appRegistrationName
            1 {$appRegistrationName = Read-Host -Prompt ("`nPlease enter a name for the app registration in Azure AD. (There is no check if the name will be valid)") -ErrorAction Stop;}
        }

    return $appRegistrationName;

}

function fnSelect-ResourceGroup(){

    [array]$myAvailabeResourceGroups = Get-AzResourceGroup;
    [bool]$myIsValid = $false;

    #if more than one ask for the desired one
    if($myAvailabeResourceGroups.count -gt 1){
         while($myIsValid -eq $false){   
            #user interaction to choose the resource group
            Write-Host ("More than one resource group found:") -ForegroundColor Green;
            for($i=0; $i -lt $myAvailabeResourceGroups.count; $i++){
                Write-Host "NR:" $i "`t" $myAvailabeResourceGroups[$i].ResourceGroupName ;
            }
            try{
                [int]$myChoice = Read-Host -Prompt ("`nPlease enter the number(NR:) of the desired resource group where the web app is running") -ErrorAction Stop;
            }catch{
                $Error.Clear();
            }

            #check if input is valid
            if($myChoice -lt $myAvailabeResourceGroups.Count -and ($myChoice -match '^\d+$')){
                #set bool to end while
                $myIsValid = $true;


                #output
                Write-Host ("thank you " + $myAvailabeResourceGroups[$myChoice].ResourceGroupName + " is set`n");         
                
                #return
                return ($myAvailabeResourceGroups[$myChoice].ResourceGroupName);  
            }
            #input is not valid
            else{
                #output 
                Write-Warning "You did not provide a valid value as input, try again";
            }
        }
    }
    else{
        return ($myAvailabeResourceGroups[0].ResourceGroupName);
    }
}

function fnSelect-WebApp($resourceGroupName){

    [array]$myAvailabeWebApp = Get-AzWebApp -ResourceGroupName $resourceGroupName;
    [bool]$myIsValid = $false;

    #if more than one ask for the desired one
    if($myAvailabeWebApp.count -gt 1){
         while($myIsValid -eq $false){   
            #user interaction to choose the resource group
            Write-Host ("More than one web app found:") -ForegroundColor Green;
            for($i=0; $i -lt $myAvailabeWebApp.count; $i++){
                Write-Host "NR:" $i "`t" $myAvailabeWebApp[$i].Name;
            }
            try{
                [int]$myChoice = Read-Host -Prompt ("`nPlease enter the number(NR:) of the desired web app") -ErrorAction Stop;
            }catch{
                $Error.Clear();
            }

            #check if input is valid
            if($myChoice -lt $myAvailabeWebApp.Count -and ($myChoice -match '^\d+$')){
                #set bool to end while
                $myIsValid = $true;


                #output
                Write-Host ("thank you " + $myAvailabeWebApp[$myChoice].Name + " is set`n");         
                
                #return
                return ($myAvailabeWebApp[$myChoice].Name);  
            }
            #input is not valid
            else{
                #output 
                Write-Warning "You did not provide a valid value as input, try again";
            }
        }
    }
    else{
        return ($myAvailabeWebApp[0].Name);
    }
}

function fnCreate-AppRegistration($appRegistrationName, $webAppHostName){
    #set up uris for app registration
    $appRegistrationHomePage = "https://" + $webAppHostName;
    $appRegistrationIdentifierUris = "https://" + $webAppHostName;
    [array]$appRegistrationReplyUrls =  ("https://" + $webAppHostName + "/.auth/login/aad/callback"), ("https://" + $webAppHostName + "/return");
    
    #try to create app registration
    Write-Host ("**try to create app registration**") -ForegroundColor Yellow;
    $azADApplication = New-AzADApplication -DisplayName $appRegistrationName -HomePage $appRegistrationHomePage -IdentifierUris $appRegistrationIdentifierUris -ReplyUrls $appRegistrationReplyUrls -Confirm -ErrorAction Stop;
        
    #output
    Write-Host ("created app registration `"{0}`"" -f $azADApplication.DisplayName) -ForegroundColor Green
    
    return $azADApplication;
}
 
function fnAskFor-AppRegistrationDeletion($appRegistrationName){
    #set info for user interaction
    $title = "Delete existing App Registration";
    $message = "Do you want to delete `"" + $appRegistrationName.DisplayName + "`" ?";  

    $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", `
        "Delete it."

    $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", `
        "Script will end."

    $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)

    $result = $host.ui.PromptForChoice($title, $message, $options, 0)

    switch ($result)
        {
            0 {Remove-Azureadapplication -ObjectId $appRegistrationName.objectId} 
            1 {return 777}
        }
    Start-Sleep -Seconds 3;
}

function fnAskFor-AddUsertoAppRole($appRoleName, $UserObject, $appID, $appRoleID, [switch]$Force){
    
    if($Force){
        New-AzureADUserAppRoleAssignment -ObjectId $UserObject.ObjectId -PrincipalId $UserObject.ObjectId -ResourceId $appID -Id $appRoleID;
      
    }
    else{
        #set info for user interaction
        $title = "Add user to App role";
        $userName = $UserObject.DisplayName;
        $message = "Do you want to add `"$userName`" to `"" + $appRoleName + "`"?";  

        $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", `
            "Add user."

        $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", `
            "Do not add user."

        $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)

        $result = $host.ui.PromptForChoice($title, $message, $options, 0)

        switch ($result)
            {
                0 {New-AzureADUserAppRoleAssignment -ObjectId $UserObject.ObjectId -PrincipalId $UserObject.ObjectId -ResourceId $appID -Id $appRoleID} 
                1 {return 777}
            }
    }
} 
    
Function AddResourcePermission($requiredAccess, $exposedPermissions, $requiredAccesses, $permissionType) {
    foreach ($permission in $requiredAccesses.Trim().Split(" ")) {
        $reqPermission = $null
        $reqPermission = $exposedPermissions | Where-Object {$_.Value -contains $permission}
        Write-Host "Collected information for $($reqPermission.Value) of type $permissionType" -ForegroundColor Green
        $resourceAccess = New-Object Microsoft.Open.AzureAD.Model.ResourceAccess
        $resourceAccess.Type = $permissionType
        $resourceAccess.Id = $reqPermission.Id    
        $requiredAccess.ResourceAccess.Add($resourceAccess)
    }
}
    
Function GetRequiredPermissions($requiredDelegatedPermissions, $requiredApplicationPermissions, $reqsp) {
    $sp = $reqsp
    $appid = $sp.AppId
    $requiredAccess = New-Object Microsoft.Open.AzureAD.Model.RequiredResourceAccess
    $requiredAccess.ResourceAppId = $appid
    $requiredAccess.ResourceAccess = New-Object System.Collections.Generic.List[Microsoft.Open.AzureAD.Model.ResourceAccess]
    if ($requiredDelegatedPermissions) {
        AddResourcePermission $requiredAccess -exposedPermissions $sp.Oauth2Permissions -requiredAccesses $requiredDelegatedPermissions -permissionType "Scope"
    } 
    if ($requiredApplicationPermissions) {
        AddResourcePermission $requiredAccess -exposedPermissions $sp.AppRoles -requiredAccesses $requiredApplicationPermissions -permissionType "Role"
    }
    return $requiredAccess
}
    
Function GenerateAppKey ($fromDate, $durationInYears, $pw) {
    $endDate = $fromDate.AddYears($durationInYears) 
    $keyId = (New-Guid).ToString();
    $key = New-Object Microsoft.Open.AzureAD.Model.PasswordCredential($null, $endDate, $keyId, $fromDate, $pw)
    return $key
}
    
Function CreateAppKey($fromDate, $durationInYears, $pw) {
    
    $testKey = GenerateAppKey -fromDate $fromDate -durationInYears $durationInYears -pw $pw
    
    while ($testKey.Value -match "\+" -or $testKey.Value -match "/") {
        Write-Host "Secret contains + or / and may not authenticate correctly. Regenerating..." -ForegroundColor Yellow
        $pw = ComputePassword
        $testKey = GenerateAppKey -fromDate $fromDate -durationInYears $durationInYears -pw $pw
    }
    Write-Host "Secret doesn't contain + or /. Continuing..." -ForegroundColor Green
    $key = $testKey
    
    return $key
}
    
Function ComputePassword {
    $aesManaged = New-Object "System.Security.Cryptography.AesManaged"
    $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
    $aesManaged.BlockSize = 128
    $aesManaged.KeySize = 256
    $aesManaged.GenerateKey()
    return [System.Convert]::ToBase64String($aesManaged.Key)
}
    
Function AddOAuth2PermissionGrants($DelegatedPermissions) {
    $resource = "https://graph.windows.net/"
    $client_id = $aadApplication.AppId
    $client_secret = $appkey.Value
    $authority = "https://login.microsoftonline.com/$tenant_id"
    $tokenEndpointUri = "$authority/oauth2/token"
    $content = "grant_type=client_credentials&client_id=$client_id&client_secret=$client_secret&resource=$resource"
    
    $Stoploop = $false
    [int]$Retrycount = "0"
    
    do {
        try {
            $response = Invoke-RestMethod -Uri $tokenEndpointUri -Body $content -Method Post -UseBasicParsing
            Write-Host "Retrieved Access Token for Azure AD Graph API" -ForegroundColor Green
            # Assign access token
            $access_token = $response.access_token
    
            $headers = @{
                Authorization = "Bearer $access_token"
            }
    
            if ($ConsentDelegatedPermissionsForAllUsers) {
                $principal = "AllPrincipals"
                $principalId = $null
            }
            else {
                $principal = "Principal"
                $principalId = (Get-AzureADUser -ObjectId $UserForDelegatedPermissions).ObjectId
            }
    
            $postbody = @{
                clientId    = $serviceprincipal.ObjectId
                consentType = $principal
                startTime   = ((get-date).AddDays(-1)).ToString("yyyy-MM-dd")
                principalId = $principalId
                resourceId  = $graphsp.ObjectId
                scope       = $DelegatedPermissions
                expiryTime  = ((get-date).AddYears(99)).ToString("yyyy-MM-dd")
            }
    
            $postbody = $postbody | ConvertTo-Json
    
            $body = Invoke-RestMethod -Uri "https://graph.windows.net/myorganization/oauth2PermissionGrants?api-version=1.6" -Body $postbody -Method POST -Headers $headers -ContentType "application/json"
            Write-Host "Created OAuth2PermissionGrants for $DelegatedPermissions" -ForegroundColor Green
    
            $Stoploop = $true
        }
        catch {
            if ($Retrycount -gt 5) {
                #Write-Host "Could not get create OAuth2PermissionGrants after 6 retries." -ForegroundColor Red
                $Stoploop = $true
            }
            else {
                Write-Host "Could not create OAuth2PermissionGrants yet. Retrying in 5 seconds..." -ForegroundColor DarkYellow
                Start-Sleep -Seconds 5
                $Retrycount ++
            }
        }
    }
    While ($Stoploop -eq $false)
}  
    
function GetOrCreateMicrosoftGraphServicePrincipal {
    #$graphsp = Get-AzureADServicePrincipal -SearchString "Microsoft Graph"
    $graphsp =  Get-AzureADServicePrincipal -All $true | ? { $_.DisplayName -eq "Microsoft graph" }
    if (!$graphsp) {
        $graphsp = Get-AzureADServicePrincipal -SearchString "Microsoft.Azure.AgregatorService"
    }
    if (!$graphsp) {
        #Login-AzureRmAccount -Credential $credential -TenantId $customer.CustomerContextId
       # New-AzureRmADServicePrincipal -ApplicationId "00000003-0000-0000-c000-000000000000"
        #$graphsp = Get-AzureADServicePrincipal -SearchString "Microsoft Graph"
        "func failed here #1"
    }
    
    return $graphsp
}

Function CreateAppRole([string] $Name, [string] $Description){
    $appRole = New-Object Microsoft.Open.AzureAD.Model.AppRole
    $appRole.AllowedMemberTypes = New-Object System.Collections.Generic.List[string]
    $appRole.AllowedMemberTypes.Add("User");
    $appRole.DisplayName = $Name
    $appRole.Id = New-Guid
    $appRole.IsEnabled = $true
    $appRole.Description = $Description
    $appRole.Value = $Name;
    return $appRole
}
  
function fnCreate-AzureADApplication($applicationName, $webAppHostName, $logoutURI){   
       
    # Set this to false to limit consent for delegated permissions to a single user ($UserForDelegatedPermissions).
    $ConsentDelegatedPermissionsForAllUsers = $true
    
    # If your initial test call required delegate permissions, set this to true. The script will retrieve an access token using the 'password' grant type instead.
    $testCallRequiresDelegatePermissions = $false
    
    # This will export information about the application to a CSV located at C:\temp\.
    # The CSV will include the Client ID and Secret of the application, so keep it safe.
    $exportApplicationInfoToCSV = $false
    
    # These endpoints are called using GET method. Please modify the script below as required.
    $URIForApplicationPermissionCall = "https://graph.microsoft.com/beta/reports/getTenantSecureScores(period=1)/content"
    $URIForDelegatedPermissionCall = "https://graph.microsoft.com/v1.0/users"
    
    # If using Delegated Permissions to execute a test call, you can specify username and password info here. 
    # I strongly recommend securing these and not including them directly on the script. 
    $UserForDelegatedPermissions = ""
    $Password = ""
     
    # Enter the required permissions below, separated by spaces eg: "Directory.Read.All Reports.Read.All Group.ReadWrite.All Directory.ReadWrite.All"
    $ApplicationPermissions = "" #"User.Read.All"
    
    # Set DelegatePermissions to $null if you only require application permissions. 
    # $DelegatedPermissions = $null
    # Otherwise, include the required delegated permissions below.
    $DelegatedPermissions = "email profile openid User.Read"
 
    #set up uris for app registration
    $appRegistrationHomePage = "https://" + $webAppHostName;
    $appRegistrationIdentifierUris = "https://" + $webAppHostName;
    [array]$appRegistrationReplyUrls =  ("https://" + $webAppHostName + "/.auth/login/aad/callback"), ("https://" + $webAppHostName + "/return");
    
    Write-Host "Creating Azure AD App for $((Get-AzureADTenantDetail).displayName)"
    
    # Check for a Microsoft Graph Service Principal. If it doesn't exist end script.
    $graphsp = GetOrCreateMicrosoftGraphServicePrincipal
        
    #check for existing application and ask for deletion
    $existingapp = $null
    $existingapp = get-azureadapplication -SearchString $applicationName
    if ($existingapp) {
        if(fnAskFor-AppRegistrationDeletion($existingapp) -eq 777){return 777};
    }
       
    $rsps = @()
    if ($graphsp) {
        $rsps += $graphsp
        $tenant_id = (Get-AzureADTenantDetail).ObjectId
        $tenantName = (Get-AzureADTenantDetail).DisplayName
        $azureadsp = Get-AzureADServicePrincipal -SearchString "Windows Azure Active Directory"
        $rsps += $azureadsp
        
        # Add Required Resources Access (Microsoft Graph)
        $requiredResourcesAccess = New-Object System.Collections.Generic.List[Microsoft.Open.AzureAD.Model.RequiredResourceAccess]
        $microsoftGraphRequiredPermissions = GetRequiredPermissions -reqsp $graphsp -requiredApplicationPermissions $ApplicationPermissions -requiredDelegatedPermissions $DelegatedPermissions
        $requiredResourcesAccess.Add($microsoftGraphRequiredPermissions)
        
        if ($DelegatedPermissions) {
            Write-Host "Delegated Permissions specified, preparing permissions for Azure AD Graph API"
            # Add Required Resources Access (Azure AD Graph)
            #$AzureADGraphRequiredPermissions = GetRequiredPermissions -reqsp $azureadsp -requiredApplicationPermissions "Directory.ReadWrite.All"
            #$requiredResourcesAccess.Add($AzureADGraphRequiredPermissions)
        }
        
        
        # Get an application key
        $pw = ComputePassword
        $fromDate = [System.DateTime]::Now
        $appKey = CreateAppKey -fromDate $fromDate -durationInYears 2 -pw $pw
        
        Write-Host "**try to create the AAD application $applicationName **" -ForegroundColor Yellow
        $aadApplication = New-AzureADApplication -DisplayName $applicationName `
            -HomePage $appRegistrationHomePage `
            -ReplyUrls $appRegistrationReplyUrls `
            -IdentifierUris $appRegistrationIdentifierUris `
            -LogoutUrl $logoutURI `
            -RequiredResourceAccess $requiredResourcesAccess `
            -PasswordCredentials $appKey      
            
            
        # Creating the Service Principal for the application
        $Global:servicePrincipal = New-AzureADServicePrincipal -AppId $aadApplication.AppId
        
        Write-Host "Assigning Permissions" -ForegroundColor Yellow
          
        # Assign application permissions to the application
        foreach ($app in $requiredResourcesAccess) {
        
            $reqAppSP = $rsps | Where-Object {$_.appid -contains $app.ResourceAppId}
            Write-Host "Assigning Application permissions for $($reqAppSP.displayName)" -ForegroundColor DarkYellow
        
            foreach ($resource in $app.ResourceAccess) {
                if ($resource.Type -match "Role") {
                    #New-AzureADServiceAppRoleAssignment -ObjectId $serviceprincipal.ObjectId `
                    #    -PrincipalId $serviceprincipal.ObjectId -ResourceId $reqAppSP.ObjectId -Id $resource.Id
                    "fail here #2"
                }
            }
           
        }
        
        # Assign delegated permissions to the application
        if ($requiredResourcesAccess.ResourceAccess -match "Scope") {
            Write-Host "Delegated Permissions found. Assigning permissions to required user"  -ForegroundColor DarkYellow
                
            foreach ($app in $requiredResourcesAccess) {
                $appDP = @()
                $reqAppSP = $rsps | Where-Object {$_.appid -contains $app.ResourceAppId}
        
                foreach ($resource in $app.ResourceAccess) {
                    if ($resource.Type -match "Scope") {
                        $permission = $graphsp.oauth2permissions | Where-Object {$_.id -contains $resource.Id}
                        $appDP += $permission.Value
                    }
                }
                if ($appDP) {
                    Write-Host "Adding $appDP to user" -ForegroundColor DarkYellow
                    $appDPString = $appDp -join " "
                    AddOAuth2PermissionGrants -DelegatedPermissions $appDPString
                }
            }
        }
            
        Write-Host "App Created" -ForegroundColor Green
          
        # Define parameters for Microsoft Graph access token retrieval
        $client_id = $aadApplication.AppId;
        $client_secret = $appkey.Value
        $tenant_id = (Get-AzureADTenantDetail).ObjectId
        $resource = "https://graph.microsoft.com"
        $authority = "https://login.microsoftonline.com/$tenant_id"
        $tokenEndpointUri = "$authority/oauth2/token"
        
        # Get the access token using grant type password for Delegated Permissions or grant type client_credentials for Application Permissions
        if ($DelegatedPermissions -and $testCallRequiresDelegatePermissions) { 
            $content = "grant_type=password&client_id=$client_id&client_secret=$client_secret&username=$UserForDelegatedPermissions&password=$Password&resource=$resource";
            $testCallUri = $UriForDelegatedPermissionCall
        }
        else {
            $content = "grant_type=client_credentials&client_id=$client_id&client_secret=$client_secret&resource=$resource"
            $testCallUri = $UriForApplicationPermissionCall
        }
            
            
        # Try to execute the API call 6 times
        
        $Stoploop = $false
        [int]$Retrycount = "0"
        do {
            try {
                $response = Invoke-RestMethod -Uri $tokenEndpointUri -Body $content -Method Post -UseBasicParsing
                Write-Host "Retrieved Access Token" -ForegroundColor Green
                # Assign access token
                $access_token = $response.access_token
                $body = $null
        
                $body = Invoke-RestMethod `
                    -Uri $testCallUri `
                    -Headers @{"Authorization" = "Bearer $access_token"} `
                    -ContentType "application/json" `
                    -Method GET
                        
                Write-Host "Retrieved Graph content" -ForegroundColor Green
                $Stoploop = $true
            }
            catch {
                if ($Retrycount -gt 6) {
                    #Write-Host "Could not get Graph content after 7 retries." -ForegroundColor Red
                    $Stoploop = $true
                }
                else {
                    Write-Host "Could not get Graph content. Retrying in 5 seconds..." -ForegroundColor DarkYellow
                    Start-Sleep -Seconds 5
                    $Retrycount ++
                }
            }
        }
        While ($Stoploop -eq $false)
        
        if ($exportApplicationInfoToCSV) {
            $appProperties = @{
                ApplicationName        = $ApplicationName
                TenantName             = $tenantName
                TenantId               = $tenant_id
                clientId               = $client_id
                clientSecret           = $client_secret
                ApplicationPermissions = $ApplicationPermissions
                DelegatedPermissions   = $DelegatedPermissions
            }
            
            $AppInfo = New-Object PSObject -Property $appProperties
            $AppInfo | Select-Object ApplicationName, TenantName, TenantId, clientId, clientSecret, `
                ApplicationPermissions, DelegatedPermissions | Export-Csv C:\temp\AzureADApps.csv -Append -NoTypeInformation
        }
        return $aadApplication;      
    }
    else {
        Write-Host "Microsoft Graph Service Principal could not be found or created" -ForegroundColor Red
    }
}


#reset vars
$Error.Clear();
$servicePrincipal = $null;

#check for local admin privs
#if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")){  
#  $arguments = "& '" +$myinvocation.mycommand.definition + "'"
#  Start-Process powershell -Verb runAs -ArgumentList $arguments
#  Break
#}


#install/import needed modules
#Import-Module AzureAD
#Import-Module Az

#login to azure
if($subscriptionID){ 
    fnLogin-Azure -subscriptionID ($subscriptionID);
}
else{
    #if empty define as null
    #$subscriptionID = $null;
    $subscriptionID = fnLogin-AzureWithOutSubscription;
}
if(fncheckFor-Error -eq 777){fnLogout-all; return 777;}


#ask for name of resource group
if(!($resourceGroupName)){
    $resourceGroupName = fnSelect-ResourceGroup;
    if(fncheckFor-Error -eq 777){fnLogout-all; return 778;}
}

#set resource group object
$resourceGroup = $null; 
$resourceGroup = fnSet-ResourceGroup -resourceGroupName $resourceGroupName;
if($resourceGroup -eq 777){fnLogout-all; return 779;};


#if app name is not provided get and show possible web apps
if(!($appName)){
    $appName = fnSelect-WebApp -resourceGroupName $resourceGroupName;
    if($resourceGroup -eq 777){fnLogout-all; return 780;};
}

#set web app object
$webapp = $null;
$webApp = fnSet-WebApp -resourceGroupName $resourceGroupName -appName $appName;
if($webApp -eq 777){fnLogout-all; return 781;};

#stop web app 
Write-Host ("**try to stop web app**") -ForegroundColor Yellow;
Stop-AzWebApp -ResourceGroupName $resourceGroupName -Name $appName | out-null;

#set some vars
$appRegistrationName = $webApp.Name.ToLower().Replace('-','')
$webAppHostName = $webapp.DefaultHostName.ToLower();

#show web app host name (sometimes azure changes from "azurewebsites.net" to "3azurewebsites.net"
Write-Host ("default host name is `"{0}`"" -f $webAppHostName) -ForegroundColor Green;

#define name for app reg in Azure AD
$appRegistrationName = fnSet-AppRegistrationName -appRegistrationName $appRegistrationName;

#login azure AD
fnLogin-AzureAD -TenantID $TenantID;

#create Azure AD app and Service Prinzipal 
$azADApplication = fnCreate-AzureADApplication -applicationName $appRegistrationName -webAppHostName $webAppHostName
if($azADApplication -eq 777){fnLogout-all; return 782};



#create app roles
Write-Host ("**try to create app roles**") -ForegroundColor Yellow;

$appObjectId = $azADApplication.objectid
$app = Get-AzureADApplication -ObjectId $appObjectId
$appRoles = $app.AppRoles
Write-Host "App Roles before addition of new role.."
Write-Host $appRoles

$newRoleSuperUser = CreateAppRole -Name "Superuser" -Description "Administrators";
$appRoles.Add($newRoleSuperUser);
$newRoleAllUser = CreateAppRole -Name "Alluser" -Description "User";
$appRoles.Add($newRoleAllUser);

#set app roles settings and enable access tokens for implicit flows
Set-AzureADApplication -ObjectId $azADApplication.ObjectId -AppRoles $appRoles -oauth2AllowImplicitFlow $true;

#authentication web app 
Write-Host ("**try to set authentication settings**") -ForegroundColor Yellow ;
$resourceType = "Microsoft.Web/sites/config";
$resourceName =  $webapp.Name + "/authsettings";

#$issuerURI = "https://sts.windows.net/" + (Get-AzureADTenantDetail).ObjectId + "/";
#$resource = Invoke-AzResourceAction -ResourceGroupName grafanaforomicron -ResourceType $resourceType -ResourceName $resourceName -Action list -ApiVersion 2020-09-01 -Force;
#$resource.properties

#prepare settings
$PropertiesObject = @{
    "enabled" = "True";
    "unauthenticatedClientAction" = "0";
    "defaultProvider" = "AzureActiveDirectory";
    "tokenStoreEnabled" = "True";
    "clientId" = $azADApplication.AppId;
    "issuer" = "https://sts.windows.net/" + (Get-AzureADTenantDetail).ObjectId + "/";
    "isAadAutoProvisioned" = "True";
}

#set Azure settings
New-AzResource -PropertyObject $PropertiesObject -ResourceGroupName $resourceGroupName -ResourceType $resourceType -ResourceName $resourceName -ApiVersion 2020-09-01 -Force;


Write-Host ("**try to set Role assignments**") -ForegroundColor Yellow;
#set current user to user/admin role in app reg
$azContext = Get-AzContext;
$azContext.Account.Id
$UserObject = Get-AzureADUser -all $true | Where-Object { $_.UserPrincipalName -match $azContext.Account.Id};

#set as user 
#New-AzureADUserAppRoleAssignment -ObjectId $UserObject.ObjectId -PrincipalId $UserObject.ObjectId -ResourceId Global:servicePrincipal.objectid -Id $newRoleAllUser.ID;
fnAskFor-AddUsertoAppRole -appRoleName $newRoleAllUser.DisplayName -UserObject $UserObject -appID $Global:servicePrincipal.objectid -appRoleID $newRoleAllUser.ID -Force;

#ask for admin
fnAskFor-AddUsertoAppRole -appRoleName $newRoleSuperUser.DisplayName -UserObject $UserObject -appID $Global:servicePrincipal.objectid -appRoleID $newRoleSuperUser.ID;

#start web app
Write-Host ("**try to start web app**") -ForegroundColor Yellow;
Start-AzWebApp -ResourceGroupName $resourceGroupName -Name $appName | out-null;
Write-Host ("##the web app need some time to initialize. Stay patient##") -ForegroundColor Green;

#open web app


#log out
fnLogout-all; 

Write-Host "`n`n`nerror count:" -ForegroundColor Red
$Error.Count

#$appRegistrationName
#$appRegistrationHomePage
#$appRegistrationIdentifierUris
#$appRegistrationReplyUrls

pause
