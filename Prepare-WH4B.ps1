#IP Prerequisites
#Templateleri export et
#Hersey GITHUB koy, download et
#Download and install RSAT
#Deployment Type
#Windows Version
#Domain Version
#Schema Version
#etc...


#Create the KeyCredential Admins Security Global Group
$KeyCredentialGroupOU = "CN=Users,DC=toynak,DC=local"
New-ADGroup -Name "Key Credential Admins" -SamAccountName KeyCredentialAdmins -GroupCategory Security -GroupScope Global -DisplayName "Key Credential Admins" -Path $KeyCredentialGroupOU -Description "Members of this group can add and remove WH4B keys."

#Create the Windows Hello for Business Users Security Global Group
$WH4BUsersGroupOU = "CN=Users,DC=toynak,DC=local"
New-ADGroup -Name "Windows Hello for Business Users" -SamAccountName WH4BUsers -GroupCategory Security -GroupScope Global -DisplayName "Windows Hello for Business Users" -Path $WH4BUsersGroupOU -Description "Members of this group will be enabled for Windows Hello for Business"

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


#Configure Domain Controller Certificates
Export-ADCSTemplate -DisplayName foo > .\foo.json

#Superseding the existing Domain Controller certificate
#Configure an Internal Web Server Certificate template
#Unpublish Superseded Certificate Templates
#Publish Certificate Templates to the Certificate Authority
#Configure Domain Controllers for Automatic Certificate Enrollment
#Deploy the Domain Controller Auto Certificate Enrollment Group Policy Object
#Prepare and Deploy Windows Server 2016 Active Directory Federation Services
Install-AdfsFarm -CertificateThumbprint 8169c52b4ec6e77eb2ae17f028fe5da4e35c0bed -FederationServiceName fs.corp.contoso.com -GroupServiceAccountIdentifier CONTOSO\GroupAccount01
#Validate and Deploy Multifactor Authentication Services (MFA)
#Configure Windows Hello for Business Policy settings