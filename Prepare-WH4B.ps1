#IP Prerequisites
#Download and install RSAT
#Deployment Type
#Windows Version
#Domain Version
#Schema Version
#etc...


#Create the KeyCredential Admins Security Global Group
$keyCredentialGroupOU = "CN=Users,DC=toynak,DC=local"
New-ADGroup -Name "Key Credential Admins" -SamAccountName KeyCredentialAdmins -GroupCategory Security -GroupScope Global -DisplayName "Key Credential Admins" -Path $keyCredentialGroupOU -Description "Members of this group can add and remove WH4B keys."

#Create the Windows Hello for Business Users Security Global Group
$wH4BUsersGroupOU = "CN=Users,DC=toynak,DC=local"
New-ADGroup -Name "Windows Hello for Business Users" -SamAccountName WH4BUsers -GroupCategory Security -GroupScope Global -DisplayName "Windows Hello for Business Users" -Path $wH4BUsersGroupOU -Description "Members of this group will be enabled for Windows Hello for Business"

#Install the Active Directory Certificate Services role
Add-WindowsFeature Adcs-Cert-Authority –IncludeManagementTools
Install-AdcsCertificationAuthority

#To create certificate templates (on Tools Machine)
#Install Remote Administration Tools from https://www.microsoft.com/en-us/download/details.aspx?id=45520
#PreRequisites Powershell 5.x
#Enterprise Admin rights
#Download JSON
Set-ExecutionPolicy Unrestricted
Install-Module ADCSTemplate

#Create Working Directory
$deploymentSource = "C:\WH4BDeployment"
$domainNetBIOS = "CORP"
New-Item -Path $deploymentSource -ItemType Directory -Force
Set-Location -Path $deploymentSource

#Configure Domain Controller Certificates
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/yagmurs/wh4b/master/wh4b-adcs-dc-template.json" -OutFile $deploymentSource\wh4b-adcs-dc-template.json
New-ADCSTemplate -DisplayName "Domain Controller Authentication (Kerberos)" -JSON (Get-Content -Path $deploymentSource\wh4b-adcs-dc-template.json -Raw) -Identity "$domainNetBIOS\domain controllers" -AutoEnroll

#Superseding the existing Domain Controller Certificate
#Configure an Internal Web Server Certificate template
#Unpublish Superseded Certificate Templates
#Publish Certificate Templates to the Certificate Authority
#Configure Domain Controllers for Automatic Certificate Enrollment
#Deploy the Domain Controller Auto Certificate Enrollment Group Policy Object
#Prepare and Deploy Windows Server 2016 Active Directory Federation Services
$certificateThumbprint = ""
$federationServiceName = "sts.corp.contoso.com"
$groupManagedServiceAccount = "CONTOSO\gmsa_ADFS"
Install-AdfsFarm -CertificateThumbprint $certificateThumbprint -FederationServiceName $federationServiceName -GroupServiceAccountIdentifier $groupManagedServiceAccount
#Validate and Deploy Multifactor Authentication Services (MFA)
#Configure Windows Hello for Business Policy settings