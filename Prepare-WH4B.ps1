#IP Prerequisites
#Download and install RSAT
#Deployment Type
#Windows Version
#Domain Version
#Schema Version
#etc...
#global variables
$domainFQDN = "corp.toynak.club"
$domainDistinguishedName = "DC=" + ($domainFQDN.Split(".") -join ",DC=")
$domainNetBIOS = $domainFQDN.Split(".")[0]
$caServerName = "ca1.$domainFQDN"
$adfsServerName = "adfs1.$domainFQDN"
$certificateThumbprint = ""
$federationServiceName = "sts.toynak.club"
$groupManagedServiceAccount = "corp\gmsa_ADFS$"

#Create the KeyCredential Admins Security Global Group
$keyCredentialGroupOUdn = "CN=Users,$domainDistinguishedName"
New-ADGroup -Name "Key Credential Admins" -SamAccountName KeyCredentialAdmins -GroupCategory Security -GroupScope Global -DisplayName "Key Credential Admins" -Path $keyCredentialGroupOUdn -Description "Members of this group can add and remove WH4B keys."

#Create the Windows Hello for Business Users Security Global Group
$wH4BUsersGroupOUdn = "CN=Users,$domainDistinguishedName"
New-ADGroup -Name "Windows Hello for Business Users" -SamAccountName WH4BUsers -GroupCategory Security -GroupScope Global -DisplayName "Windows Hello for Business Users" -Path $wH4BUsersGroupOUdn -Description "Members of this group will be enabled for Windows Hello for Business"

#Install the Active Directory Certificate Services role
Add-WindowsFeature Adcs-Cert-Authority –IncludeManagementTools
Install-AdcsCertificationAuthority

#To create certificate templates (on Tools Machine)
#Export-ADCSTemplate -DisplayName "Domain Controller Authentication (Kerberos)" > $deploymetSource\dcauthentication.json

#Install Remote Administration Tools from https://www.microsoft.com/en-us/download/details.aspx?id=45520

#PreRequisites Powershell 5.x
#Enterprise Admin rights
#Download JSON
Set-ExecutionPolicy Unrestricted
Install-Module ADCSTemplate

#Create Working Directory
$deploymentSource = "C:\WH4BDeployment"
New-Item -Path $deploymentSource -ItemType Directory -Force
Set-Location -Path $deploymentSource
$dcCertificateTemplateDisplayName = "Domain Controller Authentication (Kerberos)"
$dcCertificateTemplateName = (-split $dcCertificateTemplateDisplayName) -join ""
$wh4bCertificateTemplateDisplayName = "WH4B Authentication"
$wh4bCertificateTemplateName = (-split $dcCertificateTemplateDisplayName) -join ""

#Configure Domain Controller Certificates
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/yagmurs/wh4b/master/certificate-templates/wh4b-adcs-dc-template.json" -OutFile "$deploymentSource\wh4b-adcs-dc-template.json"
New-ADCSTemplate -DisplayName $dcCertificateTemplateDisplayName -JSON (Get-Content -Path $deploymentSource\wh4b-adcs-dc-template.json -Raw) -Identity "$domainNetBIOS\domain controllers" -AutoEnroll

#Configure WH4B User Certificates
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/yagmurs/wh4b/master/certificate-templates/wh4b-adcs-wh4b-template.json" -OutFile "$deploymentSource\wh4b-adcs-dc-template.json"
New-ADCSTemplate -DisplayName $wh4bCertificateTemplateDisplayName -JSON (Get-Content -Path $deploymentSource\wh4b-adcs-wh4b-template.json -Raw) -Identity "$domainNetBIOS\Windows Hello for Business Users"




#Superseding the existing Domain Controller Certificate
Read-Host "Superseed following certificate templates on $dcCertificateTemplateDisplayName.... Kerberos Authentication, Domain Controller, and Domain Controller Authentication"
#Unpublish Superseded Certificate Templates
Enter-PSSession -ComputerName $caServerName
Get-CaTemplate
Remove-CAtemplate -Name "KerberosAuthentication"
Remove-CAtemplate -Name "DomainController"
Remove-CAtemplate -Name "DomainControllerAuthentication"
exit
#Publish Certificate Templates to the Certificate Authority
Enter-PSSession -ComputerName $caServerName
Add-CATemplate -Name $dcCertificateTemplateName -Confirm:$false
exit
Write-Host "Publish Domain Controller Authentication (Kerberos) template to appropriate CAs."


#Configure an Internal Web Server Certificate template (Optional)

#Configure Domain Controllers for Automatic Certificate Enrollment
$gpoGuid = "DA6A4F73-C1D3-44D3-A6E8-D2C9E8D3BFAE"
$dcGPOName = "Domain Controller Certificate Auto Enrollment"
$newGPO = New-GPO -Name $dcGPOName

Invoke-WebRequest -Uri "https://raw.githubusercontent.com/yagmurs/wh4b/master/resources/gpo-backups/dc.zip" -OutFile "$deploymentSource\$dcGPOName.zip"
Expand-Archive -Path "$deploymentSource\$dcGPOName.zip" -DestinationPath "$deploymentSource\$dcGPOName" -Force

Import-GPO -BackupId $gpoGuid -TargetName $dcGPOName -Path "$deploymentSource\$dcGPOName"

#Deploy the Domain Controller Auto Certificate Enrollment Group Policy Object
New-GPLink -Guid $newGPO.ID -Target "OU=domain controllers,$domainDistinguishedName"

#Prepare and Deploy Windows Server 2016 Active Directory Federation Services
Read-Host "Import ADFS Service Communication certificate to ADFS server."
#Group Manages Service Account creation
Add-KdsRootKey -EffectiveTime (Get-Date).AddHours(-10)
#Import Certificate to ADFS Server
Enter-PSSession -ComputerName $adfsServerName
Install-WindowsFeature Adfs-Federation –IncludeManagementTools
Install-AdfsFarm -CertificateThumbprint $certificateThumbprint -FederationServiceName $federationServiceName -GroupServiceAccountIdentifier $groupManagedServiceAccount
exit
#Add ADFS Service account to groups
$gmsaString = ($groupManagedServiceAccount.Split("\")[1]).replace("$","")
$gmsaObject = Get-ADObject -Filter 'name -eq $gmsaString'
Add-ADGroupMember - identity "KeyCredentialAdmins" -Members $gmsaObject
Add-ADGroupMember - identity "WH4BUsers" -Members $gmsaObject
#Validate and Deploy Multifactor Authentication Services (MFA)
#Configure Windows Hello for Business Policy settings