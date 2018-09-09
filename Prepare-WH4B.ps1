#IP Prerequisites
#Download and install RSAT
#Deployment Type
#Windows Version
#Domain Version
#Schema Version
#etc...
#global variables
#Domain FQDN - CHANGE THIS!!!!!!!!!
$domainFQDN = "corp.toynak.club"
#Domain Distinguished Name, change if not correct
$domainDistinguishedName = "DC=" + ($domainFQDN.Split(".") -join ",DC=")
#Domain NetBIOS name, change if not correct
$domainNetBIOS = $domainFQDN.Split(".")[0]
#Certificate Authority for Domain Controller Certificates
$caServerNameDC = "ca1.$domainFQDN"
#Certificate Authority for Windows Hello for Business Certificates(User and Enrollment)
$caServerNameWH4B = "ca1.$domainFQDN"
#ADFS Server Name
$adfsServerName = "adfs1.$domainFQDN"
#ADFS Service Communication Certificate Thumbprint
$certificateThumbprint = ""
#ADFS Server Communication Name
$federationServiceName = "sts.toynak.club"
#ADFS Server Group Managed Service Account name
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
$wh4bUserCertificateTemplateDisplayName = "WH4B Authentication"
$wh4bUserCertificateTemplateName = (-split $wh4bUserCertificateTemplateDisplayName) -join ""
$wh4bEnrollmentCertificateTemplateDisplayName = "WH4B Enrollment Agent"
$wh4bEnrollmentCertificateTemplateName = (-split $wh4bEnrollmentCertificateTemplateDisplayName) -join ""

#Configure Domain Controller Certificates
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/yagmurs/wh4b/master/resources/certificate-templates/wh4b-adcs-dc-template.json" -OutFile "$deploymentSource\wh4b-adcs-dc-template.json"
New-ADCSTemplate -DisplayName $dcCertificateTemplateDisplayName -JSON (Get-Content -Path $deploymentSource\wh4b-adcs-dc-template.json -Raw) -Identity "$domainNetBIOS\domain controllers" -AutoEnroll

#Configure WH4B User Certificates
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/yagmurs/wh4b/master/resources/certificate-templates/wh4b-adcs-wh4b-user-template.json" -OutFile "$deploymentSource\wh4b-adcs-wh4b-user-template.json"
New-ADCSTemplate -DisplayName $wh4bUserCertificateTemplateDisplayName -JSON (Get-Content -Path $deploymentSource\wh4b-adcs-wh4b-user-template.json -Raw) -Identity "$domainNetBIOS\WH4BUsers"

#Configure WH4B Enrollment Certificates
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/yagmurs/wh4b/master/resources/certificate-templates/wh4b-adcs-wh4b-enrollment-template.json" -OutFile "$deploymentSource\wh4b-adcs-wh4b-enrollment-template.json"
New-ADCSTemplate -DisplayName $wh4bEnrollmentCertificateTemplateDisplayName -JSON (Get-Content -Path $deploymentSource\wh4b-adcs-wh4b-enrollment-template.json -Raw) -Identity "$groupManagedServiceAccount"


#Superseding the existing Domain Controller Certificate
Read-Host "Superseed following certificate templates on $dcCertificateTemplateDisplayName.... Kerberos Authentication, Domain Controller, and Domain Controller Authentication"
#Unpublish Superseded Certificate Templates
Read-Host "Unpublish Kerberos Authentication, Domain Controller, and Domain Controller Authentication templates"
Enter-PSSession -ComputerName $caServerNameDC
Get-CaTemplate
Remove-CAtemplate -Name "KerberosAuthentication"
Remove-CAtemplate -Name "DomainController"
Remove-CAtemplate -Name "DomainControllerAuthentication"
exit
#Publish Certificate Templates to the Certificate Authority
Enter-PSSession -ComputerName $caServerNameDC
Add-CATemplate -Name $dcCertificateTemplateName -Confirm:$false
exit
Enter-PSSession -ComputerName $caServerNameWH4B
Add-CATemplate -Name $wh4bUserCertificateTemplateName -Confirm:$false
Add-CATemplate -Name $wh4bEnrollmentCertificateTemplateName -Confirm:$false
exit
#Write-Host "Published Domain Controller Authentication (Kerberos) template to appropriate CAs."


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
#Enable Device Registration
Enable-AdfsDeviceRegistration 
exit

certutil –dsTemplate $wh4bUserCertificateTemplateName msPKI-Private-Key-Flag +CTPRIVATEKEY_FLAG_HELLO_LOGON_KEY
Set-AdfsCertificateAuthority -EnrollmentAgent -EnrollmentAgentCertificateTemplate $wh4bEnrollmentCertificateTemplateName -WindowsHelloCertificateTemplate $wh4bUserCertificateTemplateName

#Add ADFS Service account to groups
$gmsaString = ($groupManagedServiceAccount.Split("\")[1]).replace("$","")
$gmsaObject = Get-ADObject -Filter 'name -eq $gmsaString'
Add-ADGroupMember - identity "KeyCredentialAdmins" -Members $gmsaObject
Add-ADGroupMember - identity "WH4BUsers" -Members $gmsaObject

#Configure Permissions for Key Registration
#Open Active Directory Users and Computers.
#Right-click your domain name from the navigation pane and click Properties.
#Click Security (if the Security tab is missing, turn on Advanced Features from the View menu).
#Click Advanced. Click Add. Click Select a principal.
#The Select User, Computer, Service Account, or Group dialog box appears. In the Enter the object name to select text box, type KeyCredential Admins. Click OK.
#In the Applies to list box, select Descendant User objects.
#Using the scroll bar, scroll to the bottom of the page and click Clear all.
#In the Properties section, select Read msDS-KeyCredentialLink and Write msDS-KeyCredentialLink.
#Click OK three times to complete the task.


#Validate and Deploy Multifactor Authentication Services (MFA)
#Configure Windows Hello for Business Policy settings