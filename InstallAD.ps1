#Collect Variable Hosts from SE Lab machine. Collects characters at position 4-6.
 
$SE_Initials = $env:computername[-7,-6,-5] -join ''
$DomainName = $SE_Initials + ".com"
 
#Update RDP Jumpbox host file for W2019 hostname and IP
Add-Content -Path C:\Windows\System32\drivers\etc\hosts -Value "172.17.0.34`tSE-$SE_Initials-W2019-DT"
Add-Content -Path C:\Windows\System32\drivers\etc\hosts -Value "172.17.0.34`tSE-$SE_Initials-W2019-DT.$SE_Initials.com"
 
#Download and Extract PSexec
Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/PSTools.zip' -OutFile 'pstools.zip'
Expand-Archive -Path 'pstools.zip' -DestinationPath "$env:TEMP\pstools"
Move-Item -Path "$env:TEMP\pstools\psexec64.exe" -Destination "C:\Windows\System32\psexec64.exe"
Remove-Item -Path "$env:TEMP\pstools" -Recurse
 
#Enable PS Remoting on Lab machines
psexec64.exe \\172.17.0.34 -accepteula -u administrator -p Crowdstrike2017! -i -w c:\ -d -h powershell.exe "Enable-PSRemoting -Force"
 
#Update local Trusted host list
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "SE-$SE_Initials-W2019-DT,SE-$SE_Initials-W2019-DT.$SE_Initials.com" -Force
 
#Update remote trusted host list
psexec64.exe \\172.17.0.34 -u administrator -p Crowdstrike2017! -i -h -d powershell.exe "Set-Item WSMan:\localhost\Client\TrustedHosts -value * -force"
 
#Active Directory Setup
$AD_Setup = {Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
Import-Module ADDSDeployment
Import-Module ActiveDirectory
$SE_Initials_2 = $env:computername[-12,-11,-10] -join ''
$DomainName = $SE_Initials_2 + ".com"
$Password = ConvertTo-SecureString -AsPlainText -String Crowdstrike2017! -Force
Install-ADDSForest -DomainName "$DomainName" -SafeModeAdministratorPassword $Password ` -DomainNetbiosName $SE_Initials_2 -DomainMode Win2012R2 -ForestMode Win2012R2 -DatabasePath "%SYSTEMROOT%\NTDS" ` -LogPath "%SYSTEMROOT%\NTDS" -SysvolPath "%SYSTEMROOT%\SYSVOL" -InstallDns -Force
}
$creduser = "administrator"
$credpass = convertto-securestring -String "Crowdstrike2017!" -AsPlainText -Force
$cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $creduser,$credpass
Invoke-Command -Computer SE-$SE_Initials-W2019-DT -Script $AD_Setup –credential $cred
 
#Pause script for 10 minutes to wait for AD Machine reboot to complete
$x = 10*60
$length = $x / 100
while($x -gt 0) {
$min = [int](([string]($x/60)).split('.')[0])
$text = " " + $min + " minutes " + ($x % 60) + " seconds left"
Write-Progress "Pausing Script while waiting for reboot to complete" -status $text -perc ($x/$length)
start-sleep -s 1
$x--
}
 
#Enable PS Remoting on Lab machines
psexec64.exe \\172.17.0.26 -u demo -p Crowdstrike2017! -i -w c:\ -d -h powershell.exe "Enable-PSRemoting -Force"
psexec64.exe \\172.17.0.30 -u demo -p Crowdstrike2017! -i -w c:\ -d -h powershell.exe "Enable-PSRemoting -Force"
psexec64.exe \\172.17.0.29 -u badguy -p Crowdstrike2017! -i -w c:\ -d -h powershell.exe "Enable-PSRemoting -Force"
 
#Update Lab machines to use new Domain Controller for DNS resolution
psexec64.exe \\172.17.0.26 -u demo -p Crowdstrike2017! -i -h netsh interface ipv4 set dns name="Ethernet" static 172.17.0.34
psexec64.exe \\172.17.0.30 -u demo -p Crowdstrike2017! -i -h netsh interface ipv4 set dns name="Ethernet" static 172.17.0.34
psexec64.exe \\172.17.0.29 -u badguy -p Crowdstrike2017! -i -h netsh interface ipv4 set dns name="Ethernet" static 172.17.0.34
 
$AD_Additional = {
#Collect Variable Hosts from SE Lab machine. Collects characters at position 10-12.
$SE_Initials_W2019 = $env:computername[-12,-11,-10] -join ''
$DomainName = $SE_Initials_W2019 + ".com"
#Update DNS Records for Lab machines
Add-DnsServerResourceRecordA -Name SE-$SE_Initials_W2019-WIN10-DT -IPv4Address 172.17.0.26 -ZoneName $DomainName
Add-DnsServerResourceRecordA -Name SE-$SE_Initials_W2019-WIN10-BL -IPv4Address 172.17.0.30 -ZoneName $DomainName
Add-DnsServerResourceRecordA -Name SE-$SE_Initials_W2019-WIN10-CO -IPv4Address 172.17.0.29 -ZoneName $DomainName
 
#AD User Creation
New-ADUser -Name “Luke Skywalker_$SE_Initials_W2019” -SamAccountName “Skywalker_$SE_Initials_W2019” -GivenName “Luke” -Surname “Skywalker_$SE_Initials_W2019” -Path “CN=Users,DC=$SE_Initials_W2019,DC=com” -AccountPassword(ConvertTo-SecureString "Crowdstrike2017!" -AsPlainText -force) -Enabled $true
New-ADUser -Name “Darth Vader_$SE_Initials_W2019” -SamAccountName “Vader_$SE_Initials_W2019” -GivenName “Darth” -Surname “Vader_$SE_Initials_W2019” -Path “CN=Users,DC=$SE_Initials_W2019,DC=com” -AccountPassword(ConvertTo-SecureString "Crowdstrike2017!" -AsPlainText -force) -Enabled $true
 
#Creds
$creduser = "demo"
$credpass = convertto-securestring -String "Crowdstrike2017!" -AsPlainText -Force
$local_cred1 = new-object -typename System.Management.Automation.PSCredential -argumentlist $creduser,$credpass
$creduser = "badguy"
$credpass = convertto-securestring -String "Crowdstrike2017!" -AsPlainText -Force
$local_cred2 = new-object -typename System.Management.Automation.PSCredential -argumentlist $creduser,$credpass
$Aduser = "$SE_Initials\administrator"
$Adpass = convertto-securestring -string "Crowdstrike2017!" -AsPlainText -Force
$Adcred2 = new-object -typename System.Management.Automation.PSCredential -argumentlist $Aduser,$Adpass
 
#Add Lab Machine's BL and DT to AD Domain
Add-computer -domainname $DomainName -credential $Adcred2 -computername SE-$SE_Initials_W2019-WIN10-DT.$SE_Initials_W2019.com, SE-$SE_Initials_W2019-WIN10-BL.$SE_Initials_W2019.com -localcredential $local_cred1 -restart
 
#Add Lab Machine CO to AD Domain
Add-computer -domainname $DomainName -credential $Adcred2 -computername SE-$SE_Initials_W2019-WIN10-CO.$SE_Initials_W2019.com -localcredential $local_cred2 -restart
}
$Aduser = "$SE_Initials_W2019\administrator"
$Adpass = convertto-securestring -string "Crowdstrike2017!" -AsPlainText -Force
$Adcred = new-object -typename System.Management.Automation.PSCredential -argumentlist $Aduser,$Adpass
Connect-PSSession -ComputerName SE-$SE_Initials-W2019-DT.$SE_Initials.com –credential $Adcred
Invoke-Command -Computer SE-$SE_Initials-W2019-DT -Script $AD_Additional –credential $Adcred
 
#Pause script for 4 minutes to wait for Lab Machine reboot's to complete
$x = 4*60
$length = $x / 100
while($x -gt 0) {
$min = [int](([string]($x/60)).split('.')[0])
$text = " " + $min + " minutes " + ($x % 60) + " seconds left"
Write-Progress "Pausing Script while waiting for reboot to complete" -status $text -perc ($x/$length)
start-sleep -s 1
$x--
}
 
#Setup AD Users as local admins on endpoints
$Local_Admin= {
#Collect Variable Hosts from SE Lab machine. Collects characters at position 10-12.
$SE_Initials_W2019 = $env:computername[-12,-11,-10] -join ''
psexec64 \\SE-$SE_Initials_W2019-WIN10-CO.$SE_Initials_W2019.com -accepteula -u $SE_Initials_W2019\administrator -p Crowdstrike2017! -i -h net localgroup "Administrators" "$SE_Initials_W2019\vader_$SE_Initials_W2019" /add
psexec64 \\SE-$SE_Initials_W2019-WIN10-DT.$SE_Initials_W2019.com -u $SE_Initials_W2019\administrator -p Crowdstrike2017! -accepteula -i -h net localgroup "Administrators" "$SE_Initials_W2019\skywalker_$SE_Initials_W2019" /add
}
 
Invoke-Command -Computer SE-$SE_Initials-W2019-DT -Script $Local_Admin –credential $Adcred