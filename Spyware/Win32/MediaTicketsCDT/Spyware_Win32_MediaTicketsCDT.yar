
rule Spyware_Win32_MediaTicketsCDT{
	meta:
		description = "Spyware:Win32/MediaTicketsCDT,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 55 20 53 74 6f 72 65 20 56 61 6c 75 65 } //01 00  RU Store Value
		$a_01_1 = {72 65 6d 6f 74 65 5f 75 70 64 61 74 65 } //01 00  remote_update
		$a_01_2 = {73 65 65 64 72 65 6d 6f 74 65 5f 75 70 64 61 74 65 } //02 00  seedremote_update
		$a_01_3 = {43 6c 69 63 6b 73 70 72 69 6e 67 20 41 75 74 6f 72 75 6e } //00 00  Clickspring Autorun
	condition:
		any of ($a_*)
 
}
rule Spyware_Win32_MediaTicketsCDT_2{
	meta:
		description = "Spyware:Win32/MediaTicketsCDT,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {6e 66 2e 6f 75 74 65 72 69 6e 66 6f 2e 63 6f 6d 2f 6e 66 34 30 34 2e 70 68 70 } //01 00  nf.outerinfo.com/nf404.php
		$a_01_1 = {25 73 3f 75 72 6c 3d 25 73 26 72 69 64 3d 25 30 31 30 2e 30 66 } //01 00  %s?url=%s&rid=%010.0f
		$a_01_2 = {7b 32 45 39 44 34 43 38 31 2d 39 46 32 37 2d 34 63 31 34 2d 42 38 30 34 2d 37 42 30 46 36 42 43 38 38 41 34 46 7d } //01 00  {2E9D4C81-9F27-4c14-B804-7B0F6BC88A4F}
		$a_01_3 = {6e 64 72 76 2e 64 6c 6c } //00 00  ndrv.dll
	condition:
		any of ($a_*)
 
}
rule Spyware_Win32_MediaTicketsCDT_3{
	meta:
		description = "Spyware:Win32/MediaTicketsCDT,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {66 70 2e 63 6c 69 63 6b 73 70 72 69 6e 67 2e 6e 65 74 2f 66 69 6e 67 65 72 70 72 69 6e 74 2e 70 68 70 } //02 00  fp.clickspring.net/fingerprint.php
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 43 6c 69 63 6b 53 70 72 69 6e 67 } //01 00  SOFTWARE\ClickSpring
		$a_01_2 = {2f 64 69 73 70 61 74 63 68 65 72 2e 70 68 70 } //02 00  /dispatcher.php
		$a_01_3 = {66 70 2e 6f 75 74 65 72 69 6e 66 6f 2e 63 6f 6d } //01 00  fp.outerinfo.com
		$a_01_4 = {36 33 2e 32 35 31 2e 31 33 35 2e 32 34 } //01 00  63.251.135.24
		$a_01_5 = {4f 75 74 65 72 69 6e 66 6f } //00 00  Outerinfo
	condition:
		any of ($a_*)
 
}
rule Spyware_Win32_MediaTicketsCDT_4{
	meta:
		description = "Spyware:Win32/MediaTicketsCDT,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 55 6e 69 6e 73 74 61 6c 6c 5c 4f 75 74 65 72 69 6e 66 6f } //01 00  Software\Microsoft\Windows\CurrentVersion\Uninstall\Outerinfo
		$a_01_1 = {5c 6f 75 74 65 72 69 6e 66 6f 2e 69 63 6f } //01 00  \outerinfo.ico
		$a_01_2 = {4f 75 74 65 72 69 6e 66 6f 20 53 65 74 75 70 } //01 00  Outerinfo Setup
		$a_01_3 = {52 65 6d 6f 76 65 73 20 4f 75 74 65 72 69 6e 66 6f 20 66 72 6f 6d 20 74 68 69 73 20 63 6f 6d 70 75 74 65 72 } //01 00  Removes Outerinfo from this computer
		$a_01_4 = {4f 75 74 65 72 69 6e 66 6f 2e 65 78 65 } //01 00  Outerinfo.exe
		$a_01_5 = {4f 75 74 65 72 69 6e 66 6f 2e 64 6c 6c } //01 00  Outerinfo.dll
		$a_01_6 = {4b 69 6c 6c 4e 44 72 76 2e 64 6c 6c } //01 00  KillNDrv.dll
		$a_01_7 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 4f 75 74 65 72 69 6e 66 6f } //00 00  C:\Program Files\Outerinfo
	condition:
		any of ($a_*)
 
}
rule Spyware_Win32_MediaTicketsCDT_5{
	meta:
		description = "Spyware:Win32/MediaTicketsCDT,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 0d 00 00 01 00 "
		
	strings :
		$a_01_0 = {6f 75 74 65 72 69 6e 66 6f 2e 63 6f 6d 2f 63 6f 6e 73 75 6d 65 72 73 20 } //01 00  outerinfo.com/consumers 
		$a_01_1 = {69 66 72 61 6d 65 } //01 00  iframe
		$a_01_2 = {61 64 2e 6f 69 6e 61 64 73 65 72 76 65 72 2e 63 6f 6d } //01 00  ad.oinadserver.com
		$a_01_3 = {45 6e 74 65 72 69 6e 67 20 47 65 74 4f 49 4e 41 64 57 69 6e 64 6f 77 73 43 6f 75 6e 74 } //01 00  Entering GetOINAdWindowsCount
		$a_01_4 = {25 25 43 4f 4e 54 45 58 54 55 41 4c 5f 4b 45 59 57 4f 52 44 53 25 25 } //01 00  %%CONTEXTUAL_KEYWORDS%%
		$a_01_5 = {25 25 43 4f 4e 54 45 58 54 55 41 4c 5f 44 4f 4d 41 49 4e 25 25 } //01 00  %%CONTEXTUAL_DOMAIN%%
		$a_01_6 = {43 4f 4e 54 45 58 54 55 41 4c } //01 00  CONTEXTUAL
		$a_01_7 = {4f 75 74 65 72 69 6e 66 6f 54 65 6d 70 } //01 00  OuterinfoTemp
		$a_01_8 = {53 4f 46 54 57 41 52 45 5c 43 6c 69 63 6b 53 70 72 69 6e 67 } //01 00  SOFTWARE\ClickSpring
		$a_01_9 = {67 6c 6f 62 61 6c 4c 69 6d 69 74 41 64 57 69 6e 64 6f 77 73 4f 70 65 6e 65 64 } //01 00  globalLimitAdWindowsOpened
		$a_01_10 = {64 69 73 70 6c 61 79 52 4f 4e 41 64 73 } //01 00  displayRONAds
		$a_01_11 = {64 69 73 70 6c 61 79 43 74 78 41 64 73 } //01 00  displayCtxAds
		$a_01_12 = {6e 75 6d 62 65 72 4f 66 41 64 73 } //00 00  numberOfAds
	condition:
		any of ($a_*)
 
}
rule Spyware_Win32_MediaTicketsCDT_6{
	meta:
		description = "Spyware:Win32/MediaTicketsCDT,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 10 00 00 01 00 "
		
	strings :
		$a_01_0 = {6f 75 74 65 72 69 6e 66 6f 2e 69 63 6f } //01 00  outerinfo.ico
		$a_01_1 = {4f 69 55 6e 69 6e 73 74 61 6c 6c 65 72 2e 65 78 65 } //01 00  OiUninstaller.exe
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 55 6e 69 6e 73 74 61 6c 6c 5c 4f 75 74 65 72 69 6e 66 6f } //02 00  Software\Microsoft\Windows\CurrentVersion\Uninstall\Outerinfo
		$a_01_3 = {4f 69 6e 55 6e 69 6e 73 74 61 6c 6c 2e 65 78 65 } //02 00  OinUninstall.exe
		$a_01_4 = {4f 75 74 65 72 69 6e 66 6f 55 70 64 61 74 65 2e 65 78 65 } //01 00  OuterinfoUpdate.exe
		$a_01_5 = {6d 61 69 6c 74 6f 3a 75 6e 69 6e 73 74 61 6c 6c 65 72 40 6f 75 74 65 72 69 6e 66 6f 2e 63 6f 6d } //01 00  mailto:uninstaller@outerinfo.com
		$a_01_6 = {5c 4f 69 6e 46 50 2e 65 78 65 } //01 00  \OinFP.exe
		$a_01_7 = {5c 4f 69 6e 41 44 49 6e 73 74 2e 65 78 65 } //01 00  \OinADInst.exe
		$a_01_8 = {5c 4b 69 6c 6c 4e 44 72 76 2e 64 6c 6c } //01 00  \KillNDrv.dll
		$a_01_9 = {4b 69 6c 6c 52 55 } //01 00  KillRU
		$a_01_10 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 4f 75 74 65 72 69 6e 66 6f } //01 00  C:\Program Files\Outerinfo
		$a_01_11 = {5b 72 65 6e 61 6d 65 5d } //04 00  [rename]
		$a_00_12 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 55 6e 69 6e 73 74 61 6c 6c 5c 4d 65 64 69 61 74 69 63 6b 65 74 73 } //04 00  Software\Microsoft\Windows\CurrentVersion\Uninstall\Mediatickets
		$a_01_13 = {4d 65 64 69 61 54 69 63 6b 65 74 73 49 6e 73 74 61 6c 6c 65 72 2e 6f 63 78 } //04 00  MediaTicketsInstaller.ocx
		$a_01_14 = {6d 74 75 6e 69 6e 73 74 2e 65 78 65 } //01 00  mtuninst.exe
		$a_01_15 = {49 6e 76 61 6c 69 64 20 63 6f 64 65 21 20 50 6c 65 61 73 65 20 74 72 79 20 61 67 61 69 6e 2e } //00 00  Invalid code! Please try again.
	condition:
		any of ($a_*)
 
}