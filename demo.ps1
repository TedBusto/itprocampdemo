#Variables to Play with Later
$user10 = Get-ADuser -filter * | Select -First 10
$user20 = Get-ADuser -filter * | Select -First 20
$user100 = Get-ADuser -filter * | Select -First 100
$group10 = Get-ADGroup -filter * | Select -First 10
$group20 = Get-ADGroup -filter * | Select -First 20


#IT Pro Camp 2019 Speech Demo

#Remote Server Administration Tools (RSAT)

#Learn about commands using the Get-Help Command
Get-Help Get-Help

#Find out more information about a command, also try -Window -Full and -Online
Get-Help Get-ADuser -Detailed

#Powershell commands are Verb-Noun format. 

#Get-Command will look for all the currently installed modules.
Get-Command *AD*

#Will return all the things you can do with ADUsers
Get-Command -Noun ADUser

#Gets user objects from Active Directory
Get-ADuser mmarbut

#-Filter searches for *Users by property
#-like, -notlike, -eq, -ne, -contains, -in, etc.
Get-ADuser -Filter {SamAccountName -like "mmarbut"}

#-AND, -OR, -NOT
Get-ADuser -Filter {(SamAccountName -like "*EBarber*") -AND (Enabled -eq "False")}

#-Filter *
Get-ADuser -filter *

#Properties- There are many different attributes in AD
Get-ADuser mmarbut -properties *

#-Properties adds properties to the Object | Select Reduces the properties
Get-ADuser mmarbut | Select-Object Name
Get-ADuser mmarbut | Select-Object Name,SamAccountName
Get-ADuser mmarbut | Select-Object MemberOf
Get-ADuser mmarbut | Select-Object -ExpandProperty MemberOf

#All the things one can do with users or accounts
Get-Command -Noun ADuser
Get-Command -Noun ADAccount

#Get an ADGroup
Get-ADGroup Role-Security

#Add or Remove a user from a security group
Add-ADGroupMember Role-Security mmarbut
Remove-ADGroupMember Role-Security mmarbut

#PrincipalGroupMembership Vs. GroupMembership
Get-ADPrincipalGroupMembership Role-Security

#User or Group Object Vs. ADObject
Get-ADuser mmarbut | Get-ADObject

#Set properties
Set-ADUser mmarbut -Manager mmarbut -Title "Lead Administrator" -Add @{Info="Telephone Notes Section";ExtensionAttribute1="Human"}
#-Add, -Replace, and -Remove are kind of weird

Get-ADAccountResultantPasswordReplicationPolicy mmarbut
Get-ADDefaultDomainPasswordPolicy

#Creating users
#Could be read out of a CSV file and created in a ForEach loop
$user = @{Name="";DisplayName="";Title="";Password=""}

$newUser = New-ADuser -Path "OU=Accounts,OU=Production,DC=ProCamp,DC=it" -Name $user.name -DisplayName $user.displayname -GivenName $user.name.Split(" ")[0] -Surname $user.name.Split(" ")[1] -SamAccountName "$($user.name[0][0])$($user.name.split(" ")[1])" -Title $user.Title -AccountPassword ($user.password | ConvertTo-SecureString -AsPlainText -Force) -ChangePasswordAtLogon $True

#Further Information:
#Powershell Training Videos:
#https://www.youtube.com/playlist?list=PLsrZV8shpwjMXYBmmGodMMQV86xsSz1si

#Powershell and Active Directory Goes into more depth than this speach
#https://www.youtube.com/playlist?list=PLIoX3-mcY80jhSJkcfQ2bdv32_LHCt-sA

