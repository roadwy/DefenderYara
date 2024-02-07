
rule Adware_Win32_ClickPotato{
	meta:
		description = "Adware:Win32/ClickPotato,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 c1 8b 4d 0c 8d 4c 08 ff 80 39 00 74 90 01 01 8b 7d 10 8b f0 2b f8 0f be 14 37 8a 92 90 01 04 88 16 46 3b f1 76 ef 90 00 } //01 00 
		$a_00_1 = {5c 5c 2e 5c 53 63 73 69 25 64 3a } //01 00  \\.\Scsi%d:
		$a_00_2 = {70 69 6e 62 61 6c 6c 63 6f 72 70 2e 63 6f 6d 2f 64 6f 77 6e 6c 6f 61 64 73 } //00 00  pinballcorp.com/downloads
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_ClickPotato_2{
	meta:
		description = "Adware:Win32/ClickPotato,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 c1 8b 4d 0c 8d 4c 08 ff 80 39 00 74 90 01 01 8b 7d 10 8b f0 2b f8 0f be 14 37 8a 92 90 01 04 88 16 46 3b f1 76 ef 90 00 } //01 00 
		$a_01_1 = {b8 60 ea 00 00 39 84 24 b4 00 00 00 73 07 89 84 24 b4 00 00 00 6a 00 } //01 00 
		$a_01_2 = {41 72 65 20 79 6f 75 20 73 75 72 65 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 63 61 6e 63 65 6c 20 74 68 65 20 64 6f 77 6e 6c 6f 61 64 3f } //00 00  Are you sure you want to cancel the download?
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_ClickPotato_3{
	meta:
		description = "Adware:Win32/ClickPotato,SIGNATURE_TYPE_PEHSTR_EXT,09 00 07 00 05 00 00 05 00 "
		
	strings :
		$a_02_0 = {43 6c 69 63 6b 50 6f 74 61 74 6f 90 02 05 53 41 48 6f 6f 6b 2e 64 6c 6c 90 00 } //01 00 
		$a_00_1 = {48 4f 4f 4b 5f 44 4c 4c 3a 20 41 44 20 70 72 6f 63 65 73 73 20 49 44 20 28 30 78 25 30 38 58 29 20 65 71 75 61 6c 73 } //01 00  HOOK_DLL: AD process ID (0x%08X) equals
		$a_00_2 = {48 4f 4f 4b 5f 44 4c 4c 3a 20 48 69 64 65 20 41 64 } //01 00  HOOK_DLL: Hide Ad
		$a_00_3 = {65 6e 61 62 6c 65 5f 74 73 5f 6c 6f 67 67 69 6e 67 } //01 00  enable_ts_logging
		$a_00_4 = {53 6f 66 74 77 61 72 65 5c 5a 61 6e 67 6f } //00 00  Software\Zango
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_ClickPotato_4{
	meta:
		description = "Adware:Win32/ClickPotato,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {6e 70 63 6c 6e 74 61 78 5f 43 6c 69 63 6b 50 6f 74 61 74 6f 90 02 05 53 41 2e 64 6c 6c 90 00 } //01 00 
		$a_00_1 = {43 00 6c 00 69 00 65 00 6e 00 74 00 55 00 4d 00 54 00 } //01 00  ClientUMT
		$a_00_2 = {43 00 6c 00 69 00 63 00 6b 00 50 00 6f 00 74 00 61 00 74 00 6f 00 4c 00 69 00 74 00 65 00 } //01 00  ClickPotatoLite
		$a_00_3 = {4e 50 5f 47 65 74 45 6e 74 72 79 50 6f 69 6e 74 73 00 4e 50 5f 49 6e 69 74 69 61 6c 69 7a 65 00 4e 50 5f 53 68 75 74 64 6f 77 6e } //00 00 
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_ClickPotato_5{
	meta:
		description = "Adware:Win32/ClickPotato,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {55 73 65 72 2d 41 67 65 6e 74 3a 20 50 69 6e 62 61 6c 6c 43 6f 72 70 2d 42 53 41 49 2f 56 45 52 5f 53 54 52 5f 43 4f 4d 4d 41 } //01 00  User-Agent: PinballCorp-BSAI/VER_STR_COMMA
		$a_03_1 = {8d 34 01 3b f7 7e 90 14 8b 4d 08 a1 90 01 04 03 c1 8b 4d 0c 8d 4c 08 ff 80 39 00 74 18 8b 7d 10 8b f0 2b f8 0f be 14 37 8a 92 90 01 04 88 16 46 3b f1 76 ef 90 00 } //01 00 
		$a_03_2 = {63 61 6c 44 72 69 76 65 00 00 00 00 50 68 79 73 69 00 00 90 01 0d 53 43 53 49 44 49 53 4b 00 00 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_ClickPotato_6{
	meta:
		description = "Adware:Win32/ClickPotato,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 c1 8b 4d 0c 8d 4c 08 ff 80 39 00 74 90 01 01 8b 7d 10 8b f0 2b f8 0f be 14 37 8a 92 90 01 04 88 16 46 3b f1 76 ef 90 00 } //01 00 
		$a_00_1 = {64 6f 77 6e 6c 6f 61 64 73 2e 73 65 65 6b 6d 6f 2e 63 6f 6d } //01 00  downloads.seekmo.com
		$a_00_2 = {65 6e 61 62 6c 65 5f 74 73 5f 6c 6f 67 67 69 6e 67 } //01 00  enable_ts_logging
		$a_00_3 = {69 63 6e 61 6d 65 7c 69 63 76 65 72 73 69 6f 6e 7c 74 69 64 7c 6f 73 7c 6c 6f 63 61 6c 65 7c 62 72 6f 77 73 65 72 7c 63 73 63 69 64 7c 68 64 69 64 7c 6d 74 } //00 00  icname|icversion|tid|os|locale|browser|cscid|hdid|mt
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_ClickPotato_7{
	meta:
		description = "Adware:Win32/ClickPotato,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 00 6c 00 69 00 63 00 6b 00 50 00 6f 00 74 00 61 00 74 00 6f 00 4c 00 69 00 74 00 65 00 53 00 41 00 } //01 00  ClickPotatoLiteSA
		$a_00_1 = {43 6c 69 63 6b 50 6f 74 61 74 6f 4c 69 74 65 41 58 2e 49 6e 66 6f } //01 00  ClickPotatoLiteAX.Info
		$a_00_2 = {4f 6e 65 38 54 53 6f 6c 75 74 69 6f 6e 73 43 6f 6e 74 40 69 6e 33 72 4e 40 6d 65 } //01 00  One8TSolutionsCont@in3rN@me
		$a_00_3 = {43 6c 69 65 6e 74 5f 42 75 69 6c 64 5f 53 74 50 61 75 6c 69 47 69 72 6c 5f } //01 00  Client_Build_StPauliGirl_
		$a_00_4 = {62 69 73 2e 31 38 30 73 6f 6c 75 74 69 6f 6e 73 2e 63 6f 6d 2b 61 64 66 6f 72 63 65 2e } //00 00  bis.180solutions.com+adforce.
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_ClickPotato_8{
	meta:
		description = "Adware:Win32/ClickPotato,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {5c 5c 2e 5c 53 63 73 69 25 64 3a } //01 00  \\.\Scsi%d:
		$a_01_1 = {2e 70 69 6e 62 61 6c 6c 63 6f 72 70 2e 63 6f 6d } //01 00  .pinballcorp.com
		$a_01_2 = {74 72 61 63 6b 65 64 65 76 65 6e 74 73 62 61 74 63 68 6d 6f 64 65 } //01 00  trackedeventsbatchmode
		$a_00_3 = {49 43 4e 61 6d 65 7c 49 43 56 65 72 73 69 6f 6e 7c 54 49 44 7c 6f 73 7c 6c 6f 63 61 6c 65 7c 62 72 6f 77 73 65 72 7c 63 73 63 69 64 7c 68 64 69 64 7c 6d 74 } //01 00  ICName|ICVersion|TID|os|locale|browser|cscid|hdid|mt
		$a_00_4 = {48 4b 45 59 5f 43 55 52 52 45 4e 54 5f 55 53 45 52 5c 53 6f 66 74 77 61 72 65 5c 44 65 62 75 67 53 65 74 74 69 6e 67 73 5f 50 6c 61 74 72 69 75 6d } //00 00  HKEY_CURRENT_USER\Software\DebugSettings_Platrium
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_ClickPotato_9{
	meta:
		description = "Adware:Win32/ClickPotato,SIGNATURE_TYPE_PEHSTR_EXT,13 00 11 00 08 00 00 05 00 "
		
	strings :
		$a_02_0 = {54 68 69 73 20 41 64 90 02 04 69 73 20 66 72 6f 6d 20 43 6c 69 63 6b 50 6f 74 61 74 6f 90 00 } //05 00 
		$a_00_1 = {43 00 6c 00 69 00 63 00 6b 00 50 00 6f 00 74 00 61 00 74 00 6f 00 2e 00 63 00 6f 00 6d 00 } //05 00  ClickPotato.com
		$a_00_2 = {25 73 26 65 72 72 6f 72 75 72 6c 3d 25 73 26 61 64 69 64 3d 25 73 26 73 74 61 74 75 73 3d 25 64 } //05 00  %s&errorurl=%s&adid=%s&status=%d
		$a_00_3 = {4f 6e 65 38 54 53 6f 6c 75 74 69 6f 6e 73 50 40 73 73 57 25 72 64 00 } //01 00 
		$a_00_4 = {53 65 61 72 63 68 20 41 73 73 69 73 74 61 6e 74 } //01 00  Search Assistant
		$a_00_5 = {2f 64 69 73 61 62 6c 65 5f 74 76 5f 61 64 73 3d 6e } //01 00  /disable_tv_ads=n
		$a_00_6 = {61 64 5f 68 69 73 74 6f 72 79 5f 63 6f 75 6e 74 00 } //01 00 
		$a_00_7 = {73 6f 66 74 77 61 72 65 5c 7a 61 6e 67 6f } //00 00  software\zango
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_ClickPotato_10{
	meta:
		description = "Adware:Win32/ClickPotato,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 05 00 "
		
	strings :
		$a_01_0 = {4e 75 6c 6c 73 6f 66 74 20 49 6e 73 74 61 6c 6c 20 53 79 73 74 65 6d } //01 00  Nullsoft Install System
		$a_00_1 = {43 6c 69 63 6b 50 6f 74 61 74 6f 20 49 6e 73 74 61 6c 6c 65 72 20 53 74 61 72 74 65 64 } //01 00  ClickPotato Installer Started
		$a_00_2 = {43 68 65 63 6b 50 65 72 6d 69 73 73 69 6f 6e 00 53 6f 66 74 77 61 72 65 5c 43 6c 69 63 6b 50 6f 74 61 74 6f } //01 00  桃捥偫牥業獳潩n潓瑦慷敲䍜楬正潐慴潴
		$a_02_3 = {43 6c 69 63 6b 50 6f 74 61 74 6f 4c 69 74 65 2e 65 78 65 90 01 04 5c 43 6c 69 63 6b 50 6f 74 61 74 6f 4c 69 74 65 2e 6c 6f 67 90 01 04 5c 43 6c 69 63 6b 50 6f 74 61 74 6f 4c 69 74 65 5f 67 64 66 2e 64 61 74 90 01 04 5c 43 6c 69 63 6b 50 6f 74 61 74 6f 4c 69 74 65 61 75 2e 64 61 74 90 01 04 5c 43 6c 69 63 6b 50 6f 74 61 74 6f 4c 69 74 65 68 6f 6f 6b 2e 64 6c 6c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_ClickPotato_11{
	meta:
		description = "Adware:Win32/ClickPotato,SIGNATURE_TYPE_PEHSTR_EXT,29 00 28 00 07 00 00 0a 00 "
		
	strings :
		$a_03_0 = {03 c1 8b 4d 0c 8d 4c 08 ff 80 39 00 74 90 01 01 8b 7d 10 8b f0 2b f8 0f be 14 37 8a 92 90 01 04 88 16 46 3b f1 76 ef 90 00 } //0a 00 
		$a_00_1 = {5c 5c 2e 5c 53 63 73 69 25 64 3a } //0a 00  \\.\Scsi%d:
		$a_00_2 = {49 6e 73 61 74 6c 6c 53 74 61 72 74 65 64 } //0a 00  InsatllStarted
		$a_00_3 = {50 00 6c 00 65 00 61 00 73 00 65 00 20 00 77 00 61 00 69 00 74 00 20 00 77 00 68 00 69 00 6c 00 65 00 20 00 73 00 65 00 74 00 75 00 70 00 20 00 69 00 6e 00 69 00 74 00 69 00 61 00 6c 00 69 00 7a 00 65 00 73 00 } //01 00  Please wait while setup initializes
		$a_02_4 = {64 6f 77 6e 6c 6f 61 64 73 90 02 03 2e 70 6c 61 74 72 69 75 6d 2e 63 6f 6d 90 00 } //01 00 
		$a_00_5 = {64 6f 77 6e 6c 6f 61 64 73 2e 61 70 70 62 75 6e 64 6c 65 72 2e 6e 65 74 } //01 00  downloads.appbundler.net
		$a_00_6 = {66 72 65 65 6c 61 6e 64 6d 65 64 69 61 2e 63 6f 6d 2f 64 6f 77 6e 6c 6f 61 64 73 } //00 00  freelandmedia.com/downloads
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_ClickPotato_12{
	meta:
		description = "Adware:Win32/ClickPotato,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 72 65 20 79 6f 75 20 73 75 72 65 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 63 61 6e 63 65 6c 20 74 68 65 20 64 6f 77 6e 6c 6f 61 64 3f } //01 00  Are you sure you want to cancel the download?
		$a_01_1 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 25 64 00 53 43 53 49 44 49 53 4b 00 00 00 00 5c 5c 2e 5c 53 63 73 69 25 64 3a } //01 00 
		$a_01_2 = {0f b7 0e 8b c1 25 ff 0f 00 00 03 02 c1 e9 0c 03 c7 85 c9 74 0b 83 f9 03 75 06 8b 4c 24 14 01 08 83 c6 02 83 eb 01 75 d8 } //01 00 
		$a_03_3 = {0f b6 56 05 88 57 05 0f b6 4e 06 88 4f 06 0f b6 56 07 50 57 8b cb 88 57 07 e8 90 01 04 83 c6 08 83 c7 08 83 ed 01 75 9d 90 00 } //01 00 
		$a_03_4 = {8d 44 24 1c 50 8d 4c 24 24 51 8b cf e8 90 01 04 8b 57 04 8b 44 24 20 89 04 16 8b 4f 04 8b 54 24 1c 89 54 0e 04 83 c6 08 83 eb 01 75 d2 81 fe 00 10 00 00 7c c5 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_ClickPotato_13{
	meta:
		description = "Adware:Win32/ClickPotato,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 06 00 00 05 00 "
		
	strings :
		$a_00_0 = {31 00 31 00 43 00 32 00 37 00 33 00 35 00 31 00 2d 00 37 00 31 00 36 00 42 00 2d 00 34 00 30 00 35 00 32 00 2d 00 39 00 33 00 36 00 31 00 2d 00 45 00 33 00 42 00 30 00 41 00 33 00 46 00 38 00 32 00 32 00 31 00 43 00 7d 00 00 00 } //01 00 
		$a_02_1 = {67 00 65 00 74 00 72 00 90 02 02 73 00 73 00 2e 00 63 00 6c 00 90 02 02 69 00 63 00 6b 00 70 00 6f 00 74 00 61 00 90 02 02 74 00 6f 00 2e 00 63 00 6f 00 6d 00 2f 00 90 00 } //01 00 
		$a_80_2 = {48 54 4d 4c 50 6f 70 75 70 4d 65 6e 75 5f 43 6c 61 73 73 } //HTMLPopupMenu_Class  05 00 
		$a_02_3 = {43 6c 69 63 6b 50 6f 74 61 74 6f 90 02 05 53 41 42 48 4f 2e 44 4c 4c 90 00 } //05 00 
		$a_00_4 = {63 6c 69 65 6e 74 5f 62 75 69 6c 64 5f 73 74 70 61 75 6c 69 67 69 72 6c 5f } //01 00  client_build_stpauligirl_
		$a_01_5 = {63 00 6f 00 6d 00 2f 00 6c 00 69 00 74 00 65 00 6d 00 65 00 6e 00 75 00 2f 00 6d 00 65 00 6e 00 75 00 2e 00 68 00 74 00 6d 00 } //00 00  com/litemenu/menu.htm
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_ClickPotato_14{
	meta:
		description = "Adware:Win32/ClickPotato,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 07 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 c0 c3 ff 35 90 01 04 e8 90 01 04 59 c3 6a 20 68 90 01 04 e8 90 00 } //01 00 
		$a_03_1 = {56 8b 74 24 08 8b 0e 8b 01 8b 50 10 57 ff d2 83 7e 0c 00 8d 4e 0c 7c 90 01 01 3b 06 75 90 01 01 8b fe b8 01 00 00 00 f0 0f c1 01 90 00 } //01 00 
		$a_02_2 = {43 6c 69 63 6b 50 6f 74 61 74 6f 90 02 05 53 41 42 48 4f 2e 44 4c 4c 90 00 } //01 00 
		$a_00_3 = {48 00 54 00 4d 00 4c 00 50 00 6f 00 70 00 75 00 70 00 4d 00 65 00 6e 00 75 00 5f 00 43 00 6c 00 61 00 73 00 73 00 } //01 00  HTMLPopupMenu_Class
		$a_02_4 = {73 00 73 00 2e 00 63 00 6c 00 69 00 90 02 02 63 00 6b 00 70 00 90 02 06 74 00 61 00 74 00 90 00 } //01 00 
		$a_02_5 = {70 00 6f 00 74 00 61 00 74 00 6f 00 90 02 06 72 00 73 00 73 00 2e 00 63 00 6c 00 69 00 63 00 6b 00 90 00 } //01 00 
		$a_00_6 = {44 00 32 00 30 00 38 00 33 00 36 00 34 00 31 00 2d 00 45 00 35 00 37 00 46 00 2d 00 34 00 65 00 61 00 62 00 2d 00 42 00 42 00 38 00 35 00 2d 00 30 00 35 00 38 00 32 00 34 00 32 00 34 00 46 00 34 00 41 00 32 00 39 00 } //00 00  D2083641-E57F-4eab-BB85-0582424F4A29
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_ClickPotato_15{
	meta:
		description = "Adware:Win32/ClickPotato,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 0b 00 00 05 00 "
		
	strings :
		$a_02_0 = {43 6c 69 63 6b 50 6f 74 61 74 6f 90 02 05 53 41 48 6f 6f 6b 2e 64 6c 6c 90 00 } //01 00 
		$a_00_1 = {43 00 6c 00 69 00 63 00 6b 00 50 00 6f 00 74 00 61 00 74 00 6f 00 4c 00 69 00 74 00 65 00 43 00 6c 00 69 00 65 00 6e 00 74 00 49 00 63 00 6f 00 6e 00 48 00 61 00 6e 00 64 00 6c 00 65 00 } //01 00  ClickPotatoLiteClientIconHandle
		$a_00_2 = {43 00 6c 00 69 00 63 00 6b 00 50 00 6f 00 74 00 61 00 74 00 6f 00 4c 00 69 00 74 00 65 00 43 00 61 00 70 00 74 00 69 00 6f 00 6e 00 4c 00 69 00 6e 00 6b 00 } //01 00  ClickPotatoLiteCaptionLink
		$a_02_3 = {48 4f 4f 4b 5f 44 4c 4c 3a 20 48 69 64 65 20 41 90 02 08 77 69 6e 64 6f 77 20 28 30 78 25 78 29 90 00 } //01 00 
		$a_00_4 = {49 45 4c 69 73 74 65 6e 65 72 20 74 6f 6c 64 20 74 6f 20 64 69 73 63 6f 6e 6e 65 63 74 2c 20 62 75 74 } //01 00  IEListener told to disconnect, but
		$a_00_5 = {49 45 4c 69 73 74 65 6e 65 72 20 61 62 6f 75 74 20 74 6f 20 64 69 73 63 6f 6e 6e 65 63 74 2c 20 62 75 74 } //01 00  IEListener about to disconnect, but
		$a_00_6 = {48 4f 4f 4b 5f 44 4c 4c 3a 20 55 73 65 72 20 73 75 72 66 69 6e 67 20 61 77 61 79 20 66 72 6f 6d 20 6f 72 69 67 69 6e 61 6c 20 61 64 } //01 00  HOOK_DLL: User surfing away from original ad
		$a_00_7 = {48 4f 4f 4b 5f 44 4c 4c 3a 20 41 64 20 50 72 6f 70 73 20 74 69 6d 65 72 20 69 73 20 6b 69 6c 6c 65 64 20 6f 6e 20 49 45 20 77 69 6e 64 6f 77 } //01 00  HOOK_DLL: Ad Props timer is killed on IE window
		$a_02_8 = {42 69 6c 6c 79 42 6f 62 90 02 08 20 77 69 6e 64 6f 77 20 63 6c 61 73 73 20 72 65 67 69 73 74 65 72 20 65 72 72 6f 72 3a 20 25 64 2e 90 00 } //01 00 
		$a_00_9 = {48 4f 4f 4b 5f 44 4c 4c 3a 20 41 44 20 70 72 6f 63 65 73 73 20 49 44 20 28 30 78 25 30 38 58 29 20 65 71 75 61 6c 73 } //03 00  HOOK_DLL: AD process ID (0x%08X) equals
		$a_00_10 = {63 6c 69 65 6e 74 5f 62 75 69 6c 64 5f 73 74 70 61 75 6c 69 67 69 72 6c 5f } //00 00  client_build_stpauligirl_
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_ClickPotato_16{
	meta:
		description = "Adware:Win32/ClickPotato,SIGNATURE_TYPE_PEHSTR,15 00 15 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {eb 02 33 c0 8d 74 46 02 3b f3 72 b4 89 7d f4 85 ff 0f 8e 41 01 00 00 8b 5d 08 8b 0b 8b 41 f4 8b f0 2b f7 89 45 fc 89 75 ec 3b f0 7e 02 8b c6 85 c0 79 0a 68 57 00 07 80 e8 } //0a 00 
		$a_01_1 = {4e 50 5f 47 65 74 45 6e 74 72 79 50 6f 69 6e 74 73 00 4e 50 5f 49 6e 69 } //01 00  偎䝟瑥湅牴偹楯瑮s偎䥟楮
		$a_01_2 = {50 00 69 00 6e 00 62 00 61 00 6c 00 6c 00 20 00 43 00 6f 00 72 00 70 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_ClickPotato_17{
	meta:
		description = "Adware:Win32/ClickPotato,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {42 00 36 00 30 00 42 00 36 00 36 00 30 00 33 00 2d 00 41 00 43 00 43 00 46 00 2d 00 34 00 63 00 65 00 39 00 2d 00 42 00 46 00 35 00 34 00 2d 00 44 00 35 00 39 00 44 00 45 00 45 00 30 00 45 00 41 00 41 00 43 00 36 00 } //01 00  B60B6603-ACCF-4ce9-BF54-D59DEE0EAAC6
		$a_01_1 = {43 00 6c 00 69 00 63 00 6b 00 50 00 6f 00 74 00 61 00 74 00 6f 00 20 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 20 00 44 00 4c 00 4c 00 } //01 00  ClickPotato Resource DLL
		$a_01_2 = {68 74 74 70 3a 2f 2f 6f 70 65 6e 2f 3f 75 72 6c 3d } //01 00  http://open/?url=
		$a_01_3 = {69 74 73 2e 6e 6f 74 2e 6f 6b } //00 00  its.not.ok
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_ClickPotato_18{
	meta:
		description = "Adware:Win32/ClickPotato,SIGNATURE_TYPE_PEHSTR,07 00 06 00 0b 00 00 01 00 "
		
	strings :
		$a_01_0 = {5a 62 73 72 76 2e 65 78 65 } //01 00  Zbsrv.exe
		$a_01_1 = {53 42 55 53 41 2e 65 78 65 } //01 00  SBUSA.exe
		$a_01_2 = {53 41 44 46 2e 65 78 65 } //01 00  SADF.exe
		$a_01_3 = {63 6c 69 65 6e 74 61 78 70 72 6f 78 79 2e 64 6c 6c } //01 00  clientaxproxy.dll
		$a_01_4 = {26 63 6f 6d 70 5f 69 64 3d } //01 00  &comp_id=
		$a_01_5 = {53 6f 66 74 77 61 72 65 5c 5a 61 6e 67 6f } //01 00  Software\Zango
		$a_01_6 = {53 65 6e 64 69 6e 67 20 74 72 61 63 6b 65 64 20 65 76 65 6e 74 3a } //01 00  Sending tracked event:
		$a_01_7 = {65 6e 61 62 6c 65 5f 74 73 5f 6c 6f 67 67 69 6e 67 } //01 00  enable_ts_logging
		$a_01_8 = {7b 39 30 42 38 42 37 36 31 2d 44 46 32 42 2d 34 38 61 63 2d 42 42 45 30 2d 42 43 43 30 33 41 38 31 39 42 33 42 7d } //01 00  {90B8B761-DF2B-48ac-BBE0-BCC03A819B3B}
		$a_01_9 = {7b 45 31 42 41 43 46 35 35 2d 33 35 45 31 2d 34 65 34 37 2d 39 32 34 37 2d 32 44 34 38 36 36 30 45 35 35 34 35 7d } //01 00  {E1BACF55-35E1-4e47-9247-2D48660E5545}
		$a_01_10 = {7b 30 37 41 41 32 38 33 41 2d 34 33 44 37 2d 34 43 42 45 2d 41 30 36 34 2d 33 32 41 32 31 31 31 32 44 39 34 44 7d } //00 00  {07AA283A-43D7-4CBE-A064-32A21112D94D}
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_ClickPotato_19{
	meta:
		description = "Adware:Win32/ClickPotato,SIGNATURE_TYPE_PEHSTR,05 00 05 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 6f 77 6e 6c 6f 61 64 73 2e 31 38 30 73 6f 6c 75 74 69 6f 6e 73 2e 63 6f 6d 2f } //01 00  downloads.180solutions.com/
		$a_01_1 = {26 61 64 75 72 6c 3d 25 73 26 65 72 72 6f 72 75 72 6c 3d 25 73 26 61 64 69 64 3d 25 73 26 73 74 61 74 75 73 3d 25 64 } //01 00  &adurl=%s&errorurl=%s&adid=%s&status=%d
		$a_01_2 = {43 6c 69 63 6b 20 68 65 72 65 20 74 6f 20 73 74 6f 70 20 73 68 6f 77 69 6e 67 20 61 64 73 20 77 68 65 6e 20 49 20 61 6d 20 61 74 3a } //01 00  Click here to stop showing ads when I am at:
		$a_01_3 = {54 68 69 73 20 61 64 20 69 73 20 66 72 6f 6d 20 43 6c 69 63 6b 50 6f 74 61 74 6f } //01 00  This ad is from ClickPotato
		$a_01_4 = {3c 50 3e 54 6f 20 75 6e 69 6e 73 74 61 6c 6c 20 43 6c 69 63 6b 50 6f 74 61 74 6f } //01 00  <P>To uninstall ClickPotato
		$a_01_5 = {63 6c 69 63 6b 70 6f 74 61 74 6f 2e 74 76 2f } //01 00  clickpotato.tv/
		$a_01_6 = {43 00 6c 00 69 00 63 00 6b 00 50 00 6f 00 74 00 61 00 74 00 6f 00 20 00 53 00 65 00 61 00 72 00 63 00 68 00 20 00 41 00 73 00 73 00 69 00 73 00 74 00 61 00 6e 00 74 00 00 00 } //01 00 
		$a_01_7 = {42 00 79 00 20 00 63 00 6c 00 69 00 63 00 6b 00 69 00 6e 00 67 00 20 00 22 00 4b 00 65 00 65 00 70 00 20 00 43 00 6c 00 69 00 63 00 6b 00 50 00 6f 00 74 00 61 00 74 00 6f 00 } //00 00  By clicking "Keep ClickPotato
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_ClickPotato_20{
	meta:
		description = "Adware:Win32/ClickPotato,SIGNATURE_TYPE_PEHSTR,0d 00 0d 00 0c 00 00 0a 00 "
		
	strings :
		$a_01_0 = {43 00 6c 00 69 00 63 00 6b 00 50 00 6f 00 74 00 61 00 74 00 6f 00 20 00 53 00 65 00 61 00 72 00 63 00 68 00 20 00 41 00 73 00 73 00 69 00 73 00 74 00 61 00 6e 00 74 00 00 00 } //05 00 
		$a_01_1 = {53 65 61 72 63 68 20 41 73 73 69 73 74 61 6e 74 00 } //05 00 
		$a_01_2 = {4f 6e 65 38 54 53 6f 6c 75 74 69 6f 6e 73 50 40 73 73 57 25 72 64 00 } //01 00 
		$a_01_3 = {6f 6e 65 38 74 73 6f 6c 75 74 69 6f 6e 73 73 69 67 6e 40 74 75 72 33 00 } //01 00  湯㡥獴汯瑵潩獮楳湧瑀牵3
		$a_01_4 = {6f 6e 65 38 74 73 6f 6c 75 74 69 6f 6e 73 63 6f 6e 74 40 69 6e 33 72 6e 40 6d 65 00 } //01 00  湯㡥獴汯瑵潩獮潣瑮楀㍮湲浀e
		$a_01_5 = {43 6c 69 63 6b 50 6f 74 61 74 6f 4c 69 74 65 41 58 2e 49 6e 66 6f } //01 00  ClickPotatoLiteAX.Info
		$a_01_6 = {63 6f 75 6c 64 20 6e 6f 74 20 63 6f 6e 6e 65 63 74 20 74 6f 20 61 64 73 2e 61 73 70 78 00 } //01 00 
		$a_01_7 = {70 6f 70 70 69 6e 67 20 61 20 47 41 44 20 61 64 20 2d 20 61 64 20 69 64 20 28 25 73 29 20 20 6b 65 79 77 6f 72 64 20 69 64 20 28 25 73 29 } //01 00  popping a GAD ad - ad id (%s)  keyword id (%s)
		$a_01_8 = {62 6b 75 70 5f 61 64 5f 75 72 6c 00 } //01 00  止灵慟彤牵l
		$a_01_9 = {62 6b 75 70 5f 61 64 5f 75 24 72 6c 00 } //01 00 
		$a_01_10 = {44 6f 77 6e 6c 6f 61 64 73 2e 31 38 30 73 6f 6c 75 74 69 6f 6e 73 2e 63 6f 6d 2f 6b 65 79 77 6f 72 64 73 2f 00 } //01 00 
		$a_01_11 = {6e 6f 77 68 65 72 65 2e 31 38 30 73 6f 6c 75 74 69 6f 6e 73 2e 63 6f 6d 00 } //00 00 
	condition:
		any of ($a_*)
 
}