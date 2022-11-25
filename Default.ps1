
#Set-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel\' -Name '{59031a47-3f72-44a7-89c5-5595fe6b30ee}' -Value 0
#Set-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu\' -Name '{59031a47-3f72-44a7-89c5-5595fe6b30ee}' -Value 0

#Set-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel\' -Name '{20D04FE0-3AEA-1069-A2D8-08002B30309D}' -Value 0
#Set-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu\' -Name '{20D04FE0-3AEA-1069-A2D8-08002B30309D}' -Value 0

#Disable Windows Fast boot
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power\' -Name 'HiberbootEnabled' -Value 0


#default user registry modification

reg load HKU\default C:\Users\Default\NTUSER.DAT

REG ADD HKU\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Feeds /v ShellFeedsTaskbarViewMode /t REG_DWORD /d 2 /f

REG ADD HKEY_CURRENT_USER\Software\Microsoft\GameBar\ /v AutoGameModeEnabled /t REG_DWORD /d 0 /f

REG ADD HKU\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v Start_SearchFiles /t REG_DWORD /d 2 /f

REG ADD HKU\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v ShowCortanaButton /t REG_DWORD /d 0 /f

REG ADD HKU\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Search /v SearchboxTaskbarMode /t REG_DWORD /d 1 /f

REG ADD "HKU\DEFAULT\Control Panel\Keyboard" /v InitialKeyboardIndicators /t REG_SZ /d 2 /f

reg unload HKU\default


#Enables num lock for system
REG ADD "HKU\.DEFAULT\Control Panel\Keyboard" /v InitialKeyboardIndicators /t REG_SZ /d 2 /f

#Turn Off Mouse Accelaration "Enhance pointer Precision", If went to mouse options it turns on again because of windows
Set-Itemproperty -path 'HKCU:\Control Panel\Mouse' -Name 'MouseThreshold1' -value '0' -force
Set-Itemproperty -path 'HKCU:\Control Panel\Mouse' -Name 'MouseThreshold2' -value '0' -force
Set-Itemproperty -path 'HKCU:\Control Panel\Mouse' -Name 'MouseSpeed' -value '0' -force



#Starts Update Scan
C:\Windows\system32\usoclient.exe StartInteractiveScan

#set to never sleep
Powercfg /x -standby-timeout-ac 0


$url1 = "https://ninite.com/discord-notepadplusplus-steam-winrar/ninite.exe"
$output1 = "~\Downloads\ninite.exe"



Invoke-WebRequest -Uri $url1 -OutFile $output1
sleep -s 5
Start-Process -FilePath "$output1" -Verb RunAs


if((read-host "ar reikia office2021? jei ne spausk n ir enter") -like "n")
{
    Write-Host "neirasom"
}else{
    Write-Host "irasom"

    $o2021xml = "https://raw.githubusercontent.com/Upsetas/autounattendscripts/main/2021office.xml"
    $o2021xmllocal = "~\desktop\2021office.xml"


    Invoke-WebRequest -Uri $o2021xml -OutFile $o2021xmllocal
    sleep -s 1    

    $office2021Setupexe = "https://raw.githubusercontent.com/Upsetas/autounattendscripts/main/setup.exe"
    $office2021Setupexelocal = "C:\Users\Administrator\desktop\setup.exe"


    Invoke-WebRequest -Uri $office2021Setupexe -OutFile $office2021Setupexelocal
    sleep -s 2
    Start-Process -FilePath "$office2021Setupexelocal" -Verb RunAs -ArgumentList "/configure C:\Users\Administrator\desktop\2021office.xml"
  
    
}




$userName = "administrator"
Enable-LocalUser -Name $userName
Write-Host "Local Admin Password"
$Password = Read-Host
$Password = (convertto-securestring $Password -AsPlainText -Force)


Set-LocalUser -Name $userName -Password $Password
Set-LocalUser -Name $userName -PasswordNeverExpires 1
Set-LocalUser -Name $userName -AccountNeverExpires

Get-ChildItem -Path C:\Users\Public\Desktop\ | Remove-Item

Get-ChildItem -Path C:\Users\administrator\Desktop\  | Remove-Item

Write-Host "Enter Hostname"
$PCname = Read-Host
Rename-Computer -NewName "$PCname"
