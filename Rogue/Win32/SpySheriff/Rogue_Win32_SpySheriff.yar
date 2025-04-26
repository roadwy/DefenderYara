
rule Rogue_Win32_SpySheriff{
	meta:
		description = "Rogue:Win32/SpySheriff,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {4d 61 6c 77 61 72 65 42 65 6c 6c 2e 63 6f 6d } //1 MalwareBell.com
		$a_01_1 = {59 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 69 73 20 73 74 69 6c 6c 20 69 6e 66 65 63 74 65 64 21 20 41 72 65 20 79 6f 75 20 73 75 72 65 20 74 6f 20 65 78 69 74 20 6e 6f 77 3f } //1 Your computer is still infected! Are you sure to exit now?
		$a_01_2 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //1 ShellExecuteA
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule Rogue_Win32_SpySheriff_2{
	meta:
		description = "Rogue:Win32/SpySheriff,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 04 00 00 "
		
	strings :
		$a_00_0 = {45 6e 64 20 55 73 65 72 20 4c 69 63 65 6e 73 65 20 41 67 72 65 65 6d 65 6e 74 0d 0a 0d 0a 4e 4f 54 49 43 45 20 54 4f 20 55 53 45 52 3a 20 20 50 4c 45 41 53 45 20 52 45 41 44 20 54 48 49 53 20 43 4f 4e 54 52 41 43 54 20 43 41 52 45 46 55 4c 4c 59 2e } //10
		$a_00_1 = {50 6c 65 61 73 65 20 72 65 66 65 72 20 74 6f 20 74 68 65 20 } //10 Please refer to the 
		$a_00_2 = {41 72 65 20 79 6f 75 20 73 75 72 65 20 79 6f 75 20 77 69 73 68 20 74 6f 20 63 61 6e 63 65 6c 20 73 65 74 75 70 3f } //10 Are you sure you wish to cancel setup?
		$a_02_3 = {36 39 2e 35 30 2e 31 [0-05] 00 00 00 00 47 45 54 20 2f } //1
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_02_3  & 1)*1) >=31
 
}
rule Rogue_Win32_SpySheriff_3{
	meta:
		description = "Rogue:Win32/SpySheriff,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_01_0 = {53 63 61 6e 20 63 6f 6d 70 6c 65 74 65 2e 20 49 64 6c 65 2e } //1 Scan complete. Idle.
		$a_01_1 = {66 69 72 73 74 72 75 6e 2e 70 68 70 3f 69 3d 70 63 26 61 64 76 69 64 3d 25 75 20 48 54 54 50 2f 31 2e 30 } //1 firstrun.php?i=pc&advid=%u HTTP/1.0
		$a_01_2 = {63 61 6e 6e 6f 74 20 72 65 73 74 72 69 63 74 20 72 75 6e 6e 69 6e 67 20 6f 66 } //1 cannot restrict running of
		$a_01_3 = {5c 50 72 6f 74 65 63 74 65 64 5c 41 63 74 69 76 65 44 65 73 6b 74 6f 70 } //1 \Protected\ActiveDesktop
		$a_01_4 = {25 73 5c 64 72 69 76 65 72 73 5c 65 74 63 } //1 %s\drivers\etc
		$a_01_5 = {3f 61 64 76 69 64 3d 25 75 26 6c 61 6e 67 3d } //1 ?advid=%u&lang=
		$a_01_6 = {2e 70 68 70 3f 76 3d 25 75 26 64 3d 25 75 26 76 73 3d 25 75 } //1 .php?v=%u&d=%u&vs=%u
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=6
 
}
rule Rogue_Win32_SpySheriff_4{
	meta:
		description = "Rogue:Win32/SpySheriff,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 07 00 00 "
		
	strings :
		$a_00_0 = {50 65 73 74 57 69 70 65 72 20 4f 6e 6c 69 6e 65 20 49 6e 73 74 61 6c 6c 65 72 } //1 PestWiper Online Installer
		$a_00_1 = {50 65 73 74 57 69 70 65 72 2e 64 76 6d } //1 PestWiper.dvm
		$a_00_2 = {36 39 2e 35 30 2e 31 37 35 2e 31 37 39 } //2 69.50.175.179
		$a_02_3 = {47 45 54 20 2f 74 72 69 61 6c [0-02] 2e 70 68 70 3f 72 65 73 74 3d 25 75 26 76 65 72 3d 25 75 26 61 3d 30 30 30 30 30 30 30 30 20 48 54 54 50 2f 31 2e 30 } //1
		$a_00_4 = {51 66 74 75 58 6a 71 66 73 } //1 QftuXjqfs
		$a_00_5 = {41 72 65 20 79 6f 75 20 73 75 72 65 20 79 6f 75 20 77 69 73 68 20 74 6f 20 63 61 6e 63 65 6c } //1 Are you sure you wish to cancel
		$a_00_6 = {49 6e 74 65 72 6e 65 74 20 63 6f 6e 6e 65 63 74 69 6f 6e 20 6c 6f 73 73 20 64 65 74 65 63 74 65 64 2e 20 52 65 74 72 79 3f } //1 Internet connection loss detected. Retry?
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*2+(#a_02_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=5
 
}
rule Rogue_Win32_SpySheriff_5{
	meta:
		description = "Rogue:Win32/SpySheriff,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 07 00 00 "
		
	strings :
		$a_00_0 = {50 65 73 74 20 54 72 61 70 20 4f 6e 6c 69 6e 65 20 49 6e 73 74 61 6c 6c 65 72 } //1 Pest Trap Online Installer
		$a_00_1 = {50 65 73 74 54 72 61 70 2e 64 76 6d } //1 PestTrap.dvm
		$a_00_2 = {36 39 2e 35 30 2e 31 37 35 2e 31 } //2 69.50.175.1
		$a_02_3 = {47 45 54 20 2f 74 72 69 61 6c [0-02] 2e 70 68 70 3f 72 65 73 74 3d 25 75 26 76 65 72 3d 25 75 26 61 3d 30 30 30 30 30 30 [0-02] 20 48 54 54 50 2f 31 2e 30 } //1
		$a_00_4 = {51 66 74 75 55 73 62 71 } //1 QftuUsbq
		$a_00_5 = {41 72 65 20 79 6f 75 20 73 75 72 65 20 79 6f 75 20 77 69 73 68 20 74 6f 20 63 61 6e 63 65 6c 20 73 65 74 75 70 3f } //1 Are you sure you wish to cancel setup?
		$a_00_6 = {49 6e 74 65 72 6e 65 74 20 63 6f 6e 6e 65 63 74 69 6f 6e 20 6c 6f 73 73 20 64 65 74 65 63 74 65 64 2e 20 52 65 74 72 79 3f } //1 Internet connection loss detected. Retry?
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*2+(#a_02_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=5
 
}
rule Rogue_Win32_SpySheriff_6{
	meta:
		description = "Rogue:Win32/SpySheriff,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 07 00 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 41 64 77 61 72 65 52 65 6d 6f 76 65 72 } //1 SOFTWARE\AdwareRemover
		$a_00_1 = {36 39 2e 35 30 2e 31 36 37 2e 32 38 } //2 69.50.167.28
		$a_00_2 = {47 45 54 20 2f 61 72 64 6f 77 6e 6c 6f 61 64 2e 70 68 70 } //1 GET /ardownload.php
		$a_02_3 = {41 64 77 61 72 65 52 65 6d 6f 76 65 72 [0-04] 20 45 6e 64 20 55 73 65 72 20 4c 69 63 65 6e 73 65 20 41 67 72 65 65 6d 65 6e 74 } //1
		$a_02_4 = {41 64 77 61 72 65 52 65 6d 6f 76 65 72 [0-07] 20 53 65 74 75 70 } //1
		$a_00_5 = {41 72 65 20 79 6f 75 20 73 75 72 65 20 79 6f 75 20 77 69 73 68 20 74 6f 20 63 61 6e 63 65 6c 20 73 65 74 75 70 3f } //1 Are you sure you wish to cancel setup?
		$a_00_6 = {49 6e 74 65 72 6e 65 74 20 63 6f 6e 6e 65 63 74 69 6f 6e 20 69 73 20 75 6e 61 76 61 69 6c 61 62 6c 65 2e } //1 Internet connection is unavailable.
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*2+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1+(#a_02_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=5
 
}
rule Rogue_Win32_SpySheriff_7{
	meta:
		description = "Rogue:Win32/SpySheriff,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 07 00 00 "
		
	strings :
		$a_00_0 = {53 70 79 20 54 72 6f 6f 70 65 72 20 4f 6e 6c 69 6e 65 20 49 6e 73 74 61 6c 6c 65 72 } //1 Spy Trooper Online Installer
		$a_00_1 = {53 70 79 54 72 6f 6f 70 65 72 2e 64 76 6d } //1 SpyTrooper.dvm
		$a_00_2 = {36 39 2e 35 30 2e 31 37 35 2e 31 } //2 69.50.175.1
		$a_02_3 = {47 45 54 20 2f 74 72 69 61 6c [0-02] 2e 70 68 70 3f 72 65 73 74 3d 25 75 26 76 65 72 3d 25 75 26 61 3d 30 30 30 30 30 30 [0-02] 20 48 54 54 50 2f 31 2e 30 } //1
		$a_00_4 = {54 71 7a 55 73 70 70 71 66 73 } //1 TqzUsppqfs
		$a_00_5 = {41 72 65 20 79 6f 75 20 73 75 72 65 20 79 6f 75 20 77 69 73 68 20 74 6f 20 63 61 6e 63 65 6c 20 73 65 74 75 70 3f } //1 Are you sure you wish to cancel setup?
		$a_00_6 = {49 6e 74 65 72 6e 65 74 20 63 6f 6e 6e 65 63 74 69 6f 6e 20 6c 6f 73 73 20 64 65 74 65 63 74 65 64 2e 20 52 65 74 72 79 3f } //1 Internet connection loss detected. Retry?
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*2+(#a_02_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=5
 
}
rule Rogue_Win32_SpySheriff_8{
	meta:
		description = "Rogue:Win32/SpySheriff,SIGNATURE_TYPE_PEHSTR_EXT,07 00 06 00 08 00 00 "
		
	strings :
		$a_00_0 = {53 70 79 20 53 68 65 72 69 66 66 20 4f 6e 6c 69 6e 65 20 49 6e 73 74 61 6c 6c 65 72 } //1 Spy Sheriff Online Installer
		$a_00_1 = {53 70 79 53 68 65 72 69 66 66 2e 64 76 6d } //1 SpySheriff.dvm
		$a_00_2 = {36 39 2e 35 30 2e 31 37 35 2e 31 } //2 69.50.175.1
		$a_00_3 = {36 39 2e 35 30 2e 31 37 30 2e 38 33 } //2 69.50.170.83
		$a_02_4 = {47 45 54 20 2f 74 72 69 61 6c [0-02] 2e 70 68 70 3f 72 65 73 74 3d 25 75 26 76 65 72 3d 25 75 26 61 3d 30 30 30 30 30 30 30 30 20 48 54 54 50 2f 31 2e 30 } //1
		$a_00_5 = {54 71 7a 54 69 66 73 6a 67 67 } //1 TqzTifsjgg
		$a_00_6 = {41 72 65 20 79 6f 75 20 73 75 72 65 20 79 6f 75 20 77 69 73 68 20 74 6f 20 63 61 6e 63 65 6c } //1 Are you sure you wish to cancel
		$a_00_7 = {49 6e 74 65 72 6e 65 74 20 63 6f 6e 6e 65 63 74 69 6f 6e 20 6c 6f 73 73 20 64 65 74 65 63 74 65 64 2e 20 52 65 74 72 79 3f } //1 Internet connection loss detected. Retry?
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_02_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=6
 
}
rule Rogue_Win32_SpySheriff_9{
	meta:
		description = "Rogue:Win32/SpySheriff,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_02_0 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 00 49 45 44 65 66 65 6e 64 65 72 [0-05] 49 45 20 44 65 66 65 6e 64 65 72 } //1
		$a_00_1 = {49 45 20 44 65 66 65 6e 64 65 72 } //1 IE Defender
		$a_00_2 = {43 6c 69 63 6b 20 55 6e 69 6e 73 74 61 6c 6c 20 74 6f 20 73 74 61 72 74 } //1 Click Uninstall to start
		$a_00_3 = {5c 69 65 64 65 66 65 6e 64 65 72 2e 64 62 31 } //1 \iedefender.db1
		$a_00_4 = {5c 69 65 64 65 66 65 6e 64 65 72 2e 64 62 32 } //1 \iedefender.db2
		$a_00_5 = {5c 69 65 64 65 66 65 6e 64 65 72 2e 64 62 33 } //1 \iedefender.db3
		$a_00_6 = {5c 69 65 64 65 66 65 6e 64 65 72 2e 64 62 34 } //1 \iedefender.db4
		$a_00_7 = {5c 69 65 64 65 66 65 6e 64 65 72 2e 64 62 35 } //1 \iedefender.db5
		$a_00_8 = {5c 69 65 64 65 66 65 6e 64 65 72 2e 65 78 65 } //1 \iedefender.exe
		$a_00_9 = {5c 75 6e 69 6e 73 74 61 6c 6c 2e 65 78 65 } //1 \uninstall.exe
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1) >=10
 
}
rule Rogue_Win32_SpySheriff_10{
	meta:
		description = "Rogue:Win32/SpySheriff,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 09 00 00 "
		
	strings :
		$a_01_0 = {53 70 79 77 61 72 65 20 73 63 61 6e 6e 65 72 20 61 6e 64 20 72 65 6d 6f 76 65 72 2e 20 55 6e 69 6e 73 74 61 6c 6c 2e 3c 2f } //2 Spyware scanner and remover. Uninstall.</
		$a_01_1 = {53 4e 2e 53 70 79 77 61 72 65 4e 6f 55 6e 69 6e 73 74 61 6c 6c 22 0d 0a 20 20 20 20 74 } //2
		$a_01_2 = {42 53 2e 55 6e 69 6e 73 74 61 6c 6c 22 0d 0a 20 20 20 20 74 79 70 65 3d 22 77 69 6e 33 32 22 0d 0a 2f } //2
		$a_01_3 = {42 53 2e 20 55 6e 69 6e 73 74 61 6c 6c 2e 3c 2f 64 65 73 } //2 BS. Uninstall.</des
		$a_00_4 = {70 75 62 6c 69 63 4b 65 79 54 6f 6b 65 6e 3d 22 36 35 39 35 62 36 34 31 34 34 63 63 66 31 64 66 } //1 publicKeyToken="6595b64144ccf1df
		$a_00_5 = {56 61 72 69 61 6e 74 43 68 61 6e 67 65 54 79 70 65 45 78 } //1 VariantChangeTypeEx
		$a_00_6 = {49 6e 69 74 43 6f 6d 6d 6f 6e 43 6f 6e 74 72 6f 6c 73 45 78 } //1 InitCommonControlsEx
		$a_00_7 = {47 65 74 4d 6f 64 75 6c 65 48 61 6e 64 6c 65 41 } //1 GetModuleHandleA
		$a_00_8 = {47 65 74 4c 61 73 74 41 63 74 69 76 65 50 6f 70 75 70 } //1 GetLastActivePopup
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1) >=8
 
}
rule Rogue_Win32_SpySheriff_11{
	meta:
		description = "Rogue:Win32/SpySheriff,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {48 6f 73 74 3a 20 64 6f 77 6e 6c 6f 61 64 2e 73 73 64 2e 63 6f 6d } //1 Host: download.ssd.com
		$a_01_1 = {48 6f 73 74 3a 20 78 73 63 61 6e 6e 65 72 2e 73 70 79 2d 73 68 72 65 64 64 65 72 2e 63 6f 6d } //1 Host: xscanner.spy-shredder.com
		$a_01_2 = {43 61 63 68 65 2d 43 6f 6e 74 72 6f 6c 3a 20 6e 6f 2d 63 61 63 68 65 } //1 Cache-Control: no-cache
		$a_01_3 = {64 6f 77 6e 6c 6f 61 64 2e 73 70 79 2d 73 68 72 65 64 64 65 72 2e 63 6f 6d } //1 download.spy-shredder.com
		$a_03_4 = {47 45 54 20 2f 64 6c 70 2e 70 68 70 3f 26 26 6d 3d 30 26 79 64 66 3d 34 32 33 30 39 39 32 26 65 3d 30 30 30 30 30 30 30 30 26 77 3d 5f 5f 5f 5f 5f 5f ?? ?? 26 74 3d 30 26 61 70 7a 78 3d 31 26 61 70 7a 3d 6d 79 61 70 70 2e 65 78 65 20 48 54 54 50 2f 31 2e 30 } //1
		$a_01_5 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 78 70 75 70 64 61 74 65 2e 65 78 65 } //1 C:\Windows\xpupdate.exe
		$a_01_6 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 53 70 79 53 68 72 65 64 64 65 72 5c 53 70 79 53 68 72 65 64 64 65 72 2e 65 78 65 } //1 C:\Program Files\SpyShredder\SpyShredder.exe
		$a_01_7 = {36 39 2e 35 30 2e 31 36 34 2e 32 37 } //1 69.50.164.27
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}
rule Rogue_Win32_SpySheriff_12{
	meta:
		description = "Rogue:Win32/SpySheriff,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_02_0 = {5a 69 6e 61 70 73 20 41 6e 74 69 2d 53 70 79 77 61 72 65 20 32 30 30 ?? 2e 6c 6e 6b } //1
		$a_02_1 = {5a 69 6e 61 70 73 32 30 30 ?? 5c 5a 69 6e 61 70 73 2e 65 78 65 } //1
		$a_00_2 = {5a 69 6e 61 70 73 20 41 6e 74 69 2d 53 70 79 77 61 72 65 20 69 73 20 6d 69 6e 69 6d 69 7a 65 64 20 69 6e 20 74 72 61 79 20 74 6f 20 6b 65 65 70 20 79 6f 75 72 20 50 43 20 73 61 66 65 2e 20 52 69 67 68 74 20 63 6c 69 63 6b 20 69 63 6f 6e 20 74 6f 20 6f 70 65 6e 20 6f 72 20 65 78 69 74 20 74 68 65 20 70 72 6f 67 72 61 6d } //1 Zinaps Anti-Spyware is minimized in tray to keep your PC safe. Right click icon to open or exit the program
		$a_00_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Run
		$a_00_4 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 20 46 6f 6c 64 65 72 73 } //1 Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
		$a_00_5 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 41 } //1 InternetOpenA
		$a_00_6 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 } //1 InternetReadFile
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=7
 
}
rule Rogue_Win32_SpySheriff_13{
	meta:
		description = "Rogue:Win32/SpySheriff,SIGNATURE_TYPE_PEHSTR_EXT,53 00 52 00 0c 00 00 "
		
	strings :
		$a_00_0 = {47 65 74 4c 61 73 74 41 63 74 69 76 65 50 6f 70 75 70 } //10 GetLastActivePopup
		$a_01_1 = {4e 4f 54 49 43 45 20 54 4f 20 55 53 45 52 3a 20 20 50 4c 45 41 53 45 20 52 45 41 44 20 54 48 49 53 20 43 4f 4e 54 52 41 43 54 20 43 41 52 45 46 55 4c 4c 59 } //10 NOTICE TO USER:  PLEASE READ THIS CONTRACT CAREFULLY
		$a_01_2 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 25 73 5c 25 73 2e 6c 69 63 } //10 C:\Program Files\%s\%s.lic
		$a_01_3 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 25 73 5c 25 73 2e 65 78 65 } //10 C:\Program Files\%s\%s.exe
		$a_00_4 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 49 6e 74 65 72 6e 65 74 20 53 65 74 74 69 6e 67 73 } //10 Software\Microsoft\Windows\CurrentVersion\Internet Settings
		$a_01_5 = {50 72 6f 78 79 45 6e 61 62 6c 65 } //10 ProxyEnable
		$a_01_6 = {49 6e 74 65 72 6e 65 74 20 63 6f 6e 6e 65 63 74 69 6f 6e 20 69 73 20 75 6e 61 76 61 69 6c 61 62 6c 65 2e 20 54 72 79 20 61 67 61 69 6e 3f } //10 Internet connection is unavailable. Try again?
		$a_00_7 = {43 72 65 61 74 65 44 69 72 65 63 74 6f 72 79 41 } //10 CreateDirectoryA
		$a_00_8 = {26 61 64 76 69 64 3d } //1 &advid=
		$a_00_9 = {26 75 3d 25 75 26 70 3d 25 75 20 25 73 25 73 } //1 &u=%u&p=%u %s%s
		$a_00_10 = {43 6f 6e 74 72 6f 6c 3a } //1 Control:
		$a_00_11 = {30 30 30 30 32 36 35 34 } //1 00002654
	condition:
		((#a_00_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_00_4  & 1)*10+(#a_01_5  & 1)*10+(#a_01_6  & 1)*10+(#a_00_7  & 1)*10+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1+(#a_00_11  & 1)*1) >=82
 
}
rule Rogue_Win32_SpySheriff_14{
	meta:
		description = "Rogue:Win32/SpySheriff,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {64 64 65 72 2e 6c 69 63 00 00 00 00 79 53 68 72 65 00 00 00 64 64 65 72 5c 53 70 00 65 73 5c 53 70 00 00 00 25 73 25 73 25 73 25 73 25 73 25 73 00 00 00 00 64 65 72 00 79 53 68 72 65 64 00 00 53 70 00 00 61 6d 20 46 69 6c 65 73 5c 00 00 00 43 3a 5c 50 72 6f 67 72 00 00 00 00 25 73 25 73 00 00 00 00 65 73 00 00 43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 00 00 25 73 25 73 25 73 25 73 25 73 00 00 65 64 64 65 72 2e 65 78 65 00 00 00 70 79 53 68 72 00 00 00 68 72 65 64 64 65 72 5c 53 00 00 00 6c 65 73 5c 53 70 79 53 00 00 } //1
		$a_01_1 = {47 45 54 20 68 74 74 70 3a 2f 2f 64 6f 77 6e 6c 6f 61 64 2e 73 70 79 2d 73 68 72 65 64 64 65 72 2e 63 6f 6d 2f 73 73 64 6f 77 6e 6c 6f 61 64 2e 70 68 70 3f 26 61 64 76 69 64 3d 30 30 30 30 31 33 32 32 26 75 3d 25 75 26 70 3d 25 75 26 6c 61 6e 67 3d 5f 5f 5f 5f 5f 5f 5f 5f 26 76 73 3d 25 75 26 25 73 20 48 54 54 50 2f 31 2e 30 } //1 GET http://download.spy-shredder.com/ssdownload.php?&advid=00001322&u=%u&p=%u&lang=________&vs=%u&%s HTTP/1.0
		$a_01_2 = {47 45 54 20 2f 73 73 64 6f 77 6e 6c 6f 61 64 2e 70 68 70 3f 26 61 64 76 69 64 3d 30 30 30 30 31 33 32 32 26 75 3d 25 75 26 70 3d 25 75 26 6c 61 6e 67 3d 5f 5f 5f 5f 5f 5f 5f 5f 26 76 73 3d 25 75 26 25 73 20 48 54 54 50 2f 31 2e 30 } //1 GET /ssdownload.php?&advid=00001322&u=%u&p=%u&lang=________&vs=%u&%s HTTP/1.0
		$a_01_3 = {48 6f 73 74 3a 20 64 6f 77 6e 6c 6f 61 64 2e 73 70 79 2d 73 68 72 65 64 64 65 72 2e 63 6f 6d } //1 Host: download.spy-shredder.com
		$a_01_4 = {36 39 2e 35 30 2e 31 37 35 2e 31 38 30 } //1 69.50.175.180
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Rogue_Win32_SpySheriff_15{
	meta:
		description = "Rogue:Win32/SpySheriff,SIGNATURE_TYPE_PEHSTR_EXT,09 00 08 00 09 00 00 "
		
	strings :
		$a_01_0 = {48 6f 73 74 3a 20 64 6f 77 6e 6c 6f 61 64 2e 4d 61 6c 77 61 72 65 41 6c 61 72 6d 2e 63 6f 6d } //1 Host: download.MalwareAlarm.com
		$a_01_1 = {43 61 63 68 65 2d 43 6f 6e 74 72 6f 6c 3a 20 6e 6f 2d 63 61 63 68 65 } //1 Cache-Control: no-cache
		$a_03_2 = {47 45 54 20 2f 6d 61 64 6f 77 6e 6c 6f 61 64 2e 70 68 70 3f 26 61 64 76 69 64 3d 30 30 30 30 30 30 30 30 26 75 3d 30 26 70 3d 34 32 32 35 34 31 36 26 6c 61 6e 67 3d 5f 5f 5f 5f 5f 5f ?? ?? 26 76 73 3d 30 26 73 77 70 3d 31 26 61 70 78 3d 6d 79 61 70 70 2e 65 78 65 20 48 54 54 50 2f 31 2e 30 } //1
		$a_03_3 = {47 45 54 20 68 74 74 70 3a 2f 2f 64 6f 77 6e 6c 6f 61 64 2e 25 73 2e 63 6f 6d 2f 6d 61 64 6f 77 6e 6c 6f 61 64 2e 70 68 70 3f 26 61 64 76 69 64 3d 30 30 30 30 30 30 30 30 26 75 3d 25 75 26 70 3d 25 75 26 6c 61 6e 67 3d 5f 5f 5f 5f 5f 5f ?? ?? 26 76 73 3d 25 75 26 73 77 70 3d 31 26 61 70 78 3d 25 73 20 48 54 54 50 2f 31 2e 30 } //1
		$a_01_4 = {68 74 74 70 3a 2f 2f 77 77 77 2e 4d 61 6c 77 61 72 65 41 6c 61 72 6d 2e 63 6f 6d 2f } //1 http://www.MalwareAlarm.com/
		$a_01_5 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 4d 61 6c 77 61 72 65 41 6c 61 72 6d 5c 4d 61 6c 77 61 72 65 41 6c 61 72 6d 2e 65 78 65 } //1 C:\Program Files\MalwareAlarm\MalwareAlarm.exe
		$a_01_6 = {63 6f 70 79 20 22 43 3a 5c 6d 79 61 70 70 2e 65 78 65 22 20 22 43 3a 5c 57 69 6e 64 6f 77 73 5c 78 70 75 70 64 61 74 65 2e 65 78 65 22 } //1 copy "C:\myapp.exe" "C:\Windows\xpupdate.exe"
		$a_01_7 = {4d 61 6c 77 61 72 65 41 6c 61 72 6d 2e 6c 69 63 } //1 MalwareAlarm.lic
		$a_01_8 = {36 39 2e 35 30 2e 31 37 35 2e 31 38 31 } //1 69.50.175.181
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=8
 
}
rule Rogue_Win32_SpySheriff_16{
	meta:
		description = "Rogue:Win32/SpySheriff,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 45 43 54 49 4f 4e 20 38 2e 20 59 4f 55 20 41 47 52 45 45 20 54 48 41 54 20 54 48 49 53 20 41 47 52 45 45 4d 45 4e 54 20 49 53 20 45 4e 46 4f 52 43 45 41 42 4c 45 20 4c 49 4b 45 20 41 4e 59 20 57 52 49 54 54 45 4e 20 4e 45 47 4f 54 49 41 54 45 44 20 41 47 52 45 45 4d 45 4e 54 20 53 49 47 4e 45 44 20 42 59 20 59 4f 55 2e 20 20 49 46 20 59 4f 55 20 44 4f 20 4e 4f 54 20 41 47 52 45 45 2c 20 44 4f 20 4e 4f 54 20 55 53 45 20 54 48 49 53 20 53 4f 46 54 57 41 52 45 2e 20 0d 0a 0d 0a 50 6c 65 61 73 65 20 72 65 66 65 72 20 74 6f 20 74 68 65 20 77 65 62 73 69 74 65 20 66 6f 72 20 74 68 65 20 66 75 6c 6c 20 4c 69 63 65 6e 73 65 20 41 67 72 65 65 6d 65 6e 74 20 74 65 78 74 2e } //1
		$a_01_1 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 25 73 5c 25 73 2e 6c 69 63 00 00 43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 25 73 5c 25 73 00 00 43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 25 73 5c 25 73 2e 65 78 65 00 } //1
		$a_01_2 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 25 73 5c 25 73 2e 65 78 65 00 00 25 73 20 53 65 74 75 70 00 00 00 00 41 72 65 20 79 6f 75 20 73 75 72 65 20 79 6f 75 20 77 69 73 68 20 74 6f 20 63 61 6e 63 65 6c 20 73 65 74 75 70 3f 00 00 25 73 20 } //1
		$a_03_3 = {49 6e 74 65 72 6e 65 74 20 63 6f 6e 6e 65 63 74 69 6f 6e 20 69 73 20 75 6e 61 76 61 69 6c 61 62 6c 65 2e 20 54 72 79 20 61 67 61 69 6e 3f 00 00 47 45 54 20 2f 31 32 34 2e 70 68 70 3f 26 61 64 76 69 64 3d 30 30 30 30 30 ?? ?? ?? 26 75 3d 25 75 26 70 3d 25 75 20 25 73 25 73 2e 25 73 2e 63 6f 6d 0d 25 73 50 72 61 67 6d 61 3a 20 6e 6f 2d 63 61 63 68 65 0d 25 73 43 61 63 68 65 2d 43 6f 6e 74 72 6f 6c 3a 20 6e 6f 2d 63 61 63 68 65 0d 25 73 0d 25 73 00 00 00 36 39 2e 35 30 2e 31 36 37 2e 32 36 00 00 00 00 47 45 54 20 68 74 74 70 3a 2f 2f 64 6f 77 6e 6c 6f 61 64 2e 25 73 2e 63 6f 6d 2f 31 32 34 2e 70 68 70 3f 26 61 64 76 69 64 3d 30 30 30 30 30 ?? ?? ?? 26 75 3d 25 75 26 70 3d 25 75 20 25 73 25 73 2e 25 73 2e 63 6f 6d 0d 25 73 } //1
		$a_01_4 = {00 00 41 6e 74 69 53 70 79 77 61 72 65 53 68 69 65 6c 64 00 00 } //1
		$a_01_5 = {4a 42 30 31 00 00 00 00 4a 42 30 31 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
rule Rogue_Win32_SpySheriff_17{
	meta:
		description = "Rogue:Win32/SpySheriff,SIGNATURE_TYPE_PEHSTR,06 00 05 00 07 00 00 "
		
	strings :
		$a_01_0 = {64 6f 77 6e 6c 6f 61 64 2e 50 65 73 74 43 61 70 74 75 72 65 2e 63 6f 6d } //1 download.PestCapture.com
		$a_01_1 = {2f 70 63 64 6f 77 6e 6c 6f 61 64 2e 70 68 70 3f 26 } //1 /pcdownload.php?&
		$a_01_2 = {50 65 73 74 43 61 70 74 75 72 65 2e 65 78 65 } //1 PestCapture.exe
		$a_01_3 = {36 39 2e 35 30 2e 31 37 35 2e 31 } //2 69.50.175.1
		$a_01_4 = {53 4f 46 54 57 41 52 45 5c 50 65 73 74 43 61 70 74 75 72 65 53 65 74 75 70 } //1 SOFTWARE\PestCaptureSetup
		$a_01_5 = {50 65 73 74 43 61 70 74 75 72 65 20 33 2e 32 20 53 65 74 75 70 } //1 PestCapture 3.2 Setup
		$a_01_6 = {41 72 65 20 79 6f 75 20 73 75 72 65 20 79 6f 75 20 77 69 73 68 20 74 6f 20 63 61 6e 63 65 6c 20 73 65 74 75 70 3f } //1 Are you sure you wish to cancel setup?
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=5
 
}
rule Rogue_Win32_SpySheriff_18{
	meta:
		description = "Rogue:Win32/SpySheriff,SIGNATURE_TYPE_PEHSTR,06 00 05 00 07 00 00 "
		
	strings :
		$a_01_0 = {48 6f 73 74 3a 20 64 6f 77 6e 6c 6f 61 64 2e 62 72 61 76 65 73 65 6e 74 72 79 2e 63 6f 6d } //1 Host: download.bravesentry.com
		$a_01_1 = {2f 64 6f 77 6e 6c 6f 61 64 2e 70 68 70 3f 26 } //1 /download.php?&
		$a_01_2 = {42 72 61 76 65 53 65 6e 74 72 79 2e 65 78 65 } //1 BraveSentry.exe
		$a_01_3 = {36 39 2e 35 30 2e 31 37 35 2e 31 38 31 } //2 69.50.175.181
		$a_01_4 = {53 4f 46 54 57 41 52 45 5c 42 72 61 76 65 53 65 6e 74 72 79 53 65 74 75 70 } //1 SOFTWARE\BraveSentrySetup
		$a_01_5 = {42 72 61 76 65 53 65 6e 74 72 79 20 32 2e 30 20 53 65 74 75 70 } //1 BraveSentry 2.0 Setup
		$a_01_6 = {41 72 65 20 79 6f 75 20 73 75 72 65 20 79 6f 75 20 77 69 73 68 20 74 6f 20 63 61 6e 63 65 6c 20 73 65 74 75 70 3f } //1 Are you sure you wish to cancel setup?
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=5
 
}
rule Rogue_Win32_SpySheriff_19{
	meta:
		description = "Rogue:Win32/SpySheriff,SIGNATURE_TYPE_PEHSTR,06 00 05 00 07 00 00 "
		
	strings :
		$a_01_0 = {48 6f 73 74 3a 20 64 6f 77 6e 6c 6f 61 64 2e 73 70 79 2d 73 68 72 65 64 64 65 72 2e 63 6f 6d } //1 Host: download.spy-shredder.com
		$a_01_1 = {2f 73 73 64 6f 77 6e 6c 6f 61 64 2e 70 68 70 3f 26 } //1 /ssdownload.php?&
		$a_01_2 = {53 70 79 53 68 72 65 64 64 65 72 2e 65 78 65 } //1 SpyShredder.exe
		$a_01_3 = {36 39 2e 35 30 2e 31 37 35 2e 31 38 30 } //2 69.50.175.180
		$a_01_4 = {53 4f 46 54 57 41 52 45 5c 53 70 79 53 68 72 65 64 64 65 72 53 65 74 75 70 } //1 SOFTWARE\SpyShredderSetup
		$a_01_5 = {53 70 79 53 68 72 65 64 64 65 72 20 32 2e 30 20 53 65 74 75 70 } //1 SpyShredder 2.0 Setup
		$a_01_6 = {41 72 65 20 79 6f 75 20 73 75 72 65 20 79 6f 75 20 77 69 73 68 20 74 6f 20 63 61 6e 63 65 6c 20 73 65 74 75 70 3f } //1 Are you sure you wish to cancel setup?
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=5
 
}
rule Rogue_Win32_SpySheriff_20{
	meta:
		description = "Rogue:Win32/SpySheriff,SIGNATURE_TYPE_PEHSTR,06 00 05 00 07 00 00 "
		
	strings :
		$a_01_0 = {48 6f 73 74 3a 20 64 6f 77 6e 6c 6f 61 64 2e 4d 61 6c 77 61 72 65 41 6c 61 72 6d 2e 63 6f 6d } //1 Host: download.MalwareAlarm.com
		$a_01_1 = {2f 6d 61 64 6f 77 6e 6c 6f 61 64 2e 70 68 70 3f 26 } //1 /madownload.php?&
		$a_01_2 = {4d 61 6c 77 61 72 65 41 6c 61 72 6d 2e 65 78 65 } //1 MalwareAlarm.exe
		$a_01_3 = {36 39 2e 35 30 2e 31 37 35 2e 31 38 30 } //2 69.50.175.180
		$a_01_4 = {53 4f 46 54 57 41 52 45 5c 4d 61 6c 77 61 72 65 41 6c 61 72 6d 53 65 74 75 70 } //1 SOFTWARE\MalwareAlarmSetup
		$a_01_5 = {4d 61 6c 77 61 72 65 41 6c 61 72 6d 20 32 2e 30 20 53 65 74 75 70 } //1 MalwareAlarm 2.0 Setup
		$a_01_6 = {41 72 65 20 79 6f 75 20 73 75 72 65 20 79 6f 75 20 77 69 73 68 20 74 6f 20 63 61 6e 63 65 6c 20 73 65 74 75 70 3f } //1 Are you sure you wish to cancel setup?
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=5
 
}
rule Rogue_Win32_SpySheriff_21{
	meta:
		description = "Rogue:Win32/SpySheriff,SIGNATURE_TYPE_PEHSTR,06 00 05 00 07 00 00 "
		
	strings :
		$a_01_0 = {64 6f 77 6e 6c 6f 61 64 2e 4d 61 6c 77 61 72 65 2d 53 74 6f 70 70 65 72 2e 63 6f 6d } //1 download.Malware-Stopper.com
		$a_01_1 = {2f 6d 74 64 6f 77 6e 6c 6f 61 64 2e 70 68 70 3f 26 } //1 /mtdownload.php?&
		$a_01_2 = {4d 61 6c 77 61 72 65 53 74 6f 70 70 65 72 2e 65 78 65 } //1 MalwareStopper.exe
		$a_01_3 = {36 39 2e 35 30 2e 31 37 35 2e 31 } //2 69.50.175.1
		$a_01_4 = {53 4f 46 54 57 41 52 45 5c 4d 61 6c 77 61 72 65 53 74 6f 70 70 65 72 53 65 74 75 70 } //1 SOFTWARE\MalwareStopperSetup
		$a_01_5 = {4d 61 6c 77 61 72 65 53 74 6f 70 70 65 72 20 33 2e 32 20 53 65 74 75 70 } //1 MalwareStopper 3.2 Setup
		$a_01_6 = {41 72 65 20 79 6f 75 20 73 75 72 65 20 79 6f 75 20 77 69 73 68 20 74 6f 20 63 61 6e 63 65 6c 20 73 65 74 75 70 3f } //1 Are you sure you wish to cancel setup?
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=5
 
}
rule Rogue_Win32_SpySheriff_22{
	meta:
		description = "Rogue:Win32/SpySheriff,SIGNATURE_TYPE_PEHSTR,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 41 53 50 72 6f 74 65 63 74 5c 53 70 65 63 44 61 74 61 } //1 Software\ASProtect\SpecData
		$a_01_1 = {5c 5c 2e 5c 4e 54 49 43 45 } //1 \\.\NTICE
		$a_01_2 = {48 45 4c 4f 20 55 73 65 72 2e 57 69 74 68 2e 45 72 72 6f 72 } //1 HELO User.With.Error
		$a_01_3 = {70 72 6f 63 65 73 73 6f 72 41 72 63 68 69 74 65 63 74 75 72 65 3d 22 78 38 36 22 } //1 processorArchitecture="x86"
		$a_01_4 = {6e 61 6d 65 3d 22 53 4e 2e 53 70 79 77 61 72 65 4e 6f 55 6e 69 6e 73 74 61 6c 6c 22 } //1 name="SN.SpywareNoUninstall"
		$a_01_5 = {74 79 70 65 3d 22 77 69 6e 33 32 22 } //1 type="win32"
		$a_01_6 = {53 70 79 77 61 72 65 20 73 63 61 6e 6e 65 72 20 61 6e 64 20 72 65 6d 6f 76 65 72 2e 20 55 6e 69 6e 73 74 61 6c 6c 2e 3c 2f 64 65 73 63 72 69 70 74 69 6f 6e 3e } //1 Spyware scanner and remover. Uninstall.</description>
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}
rule Rogue_Win32_SpySheriff_23{
	meta:
		description = "Rogue:Win32/SpySheriff,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {5c 41 6e 76 54 72 67 72 2e 65 78 65 } //1 \AnvTrgr.exe
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 41 6e 76 54 72 67 72 73 6f 66 74 } //1 Software\AnvTrgrsoft
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 41 70 70 20 50 61 74 68 73 5c 41 6e 76 54 72 67 72 73 6f 66 74 } //1 Software\Microsoft\Windows\CurrentVersion\App Paths\AnvTrgrsoft
		$a_01_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 55 6e 69 6e 73 74 61 6c 6c 5c 41 6e 76 54 72 67 72 73 6f 66 74 } //1 Software\Microsoft\Windows\CurrentVersion\Uninstall\AnvTrgrsoft
		$a_01_4 = {68 74 74 70 3a 2f 2f 77 77 77 2e 76 69 72 74 72 69 67 67 65 72 2e 63 6f 6d } //1 http://www.virtrigger.com
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Rogue_Win32_SpySheriff_24{
	meta:
		description = "Rogue:Win32/SpySheriff,SIGNATURE_TYPE_PEHSTR,06 00 05 00 07 00 00 "
		
	strings :
		$a_01_0 = {64 6f 77 6e 6c 6f 61 64 2e 41 6e 74 69 53 70 79 53 68 69 65 6c 64 2e 63 6f 6d } //1 download.AntiSpyShield.com
		$a_01_1 = {2f 61 64 64 6f 77 6e 6c 6f 61 64 2e 70 68 70 3f 26 } //1 /addownload.php?&
		$a_01_2 = {41 6e 74 69 53 70 79 77 61 72 65 53 68 69 65 6c 64 2e 65 78 65 } //1 AntiSpywareShield.exe
		$a_01_3 = {36 39 2e 35 30 2e 31 36 37 2e 32 36 } //2 69.50.167.26
		$a_01_4 = {41 6e 74 69 53 70 79 77 61 72 65 53 68 69 65 6c 64 20 45 6e 64 20 55 73 65 72 20 4c 69 63 65 6e 73 65 20 41 67 72 65 65 6d 65 6e 74 } //1 AntiSpywareShield End User License Agreement
		$a_01_5 = {41 6e 74 69 53 70 79 77 61 72 65 53 68 69 65 6c 64 20 53 65 74 75 70 } //1 AntiSpywareShield Setup
		$a_01_6 = {41 72 65 20 79 6f 75 20 73 75 72 65 20 79 6f 75 20 77 69 73 68 20 74 6f 20 63 61 6e 63 65 6c 20 73 65 74 75 70 3f } //1 Are you sure you wish to cancel setup?
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=5
 
}
rule Rogue_Win32_SpySheriff_25{
	meta:
		description = "Rogue:Win32/SpySheriff,SIGNATURE_TYPE_PEHSTR,4c 00 4c 00 0c 00 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 41 6e 76 54 72 67 72 73 6f 66 74 } //35 Software\AnvTrgrsoft
		$a_01_1 = {68 75 69 32 32 } //35 hui22
		$a_01_2 = {73 65 67 70 61 79 2e 63 6f 6d } //5 segpay.com
		$a_01_3 = {76 69 72 75 73 74 72 69 67 67 65 72 32 30 30 39 2e 63 6f 6d } //5 virustrigger2009.com
		$a_01_4 = {76 69 72 75 73 2d 74 72 69 67 67 65 72 73 2e 63 6f 6d } //5 virus-triggers.com
		$a_01_5 = {73 79 73 74 65 6d 74 72 69 67 67 65 72 2e 63 6f 6d } //5 systemtrigger.com
		$a_01_6 = {76 69 72 75 73 2d 74 72 69 67 67 65 72 2e 63 6f 6d } //5 virus-trigger.com
		$a_01_7 = {76 69 72 74 72 69 67 67 65 72 2e 63 6f 6d } //5 virtrigger.com
		$a_01_8 = {68 74 74 70 3a 2f 2f 25 73 2f 73 79 6e 63 2e 70 68 70 } //1 http://%s/sync.php
		$a_01_9 = {68 74 74 70 3a 2f 2f 25 73 2f 66 65 61 74 75 72 65 73 2e 70 68 70 } //1 http://%s/features.php
		$a_01_10 = {68 74 74 70 3a 2f 2f 25 73 2f 73 75 70 70 6f 72 74 2e 70 68 70 } //1 http://%s/support.php
		$a_01_11 = {68 74 74 70 3a 2f 2f 25 73 2f 62 75 79 5f 6f 6e 6c 69 6e 65 2e 70 68 70 } //1 http://%s/buy_online.php
	condition:
		((#a_01_0  & 1)*35+(#a_01_1  & 1)*35+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*5+(#a_01_5  & 1)*5+(#a_01_6  & 1)*5+(#a_01_7  & 1)*5+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1) >=76
 
}
rule Rogue_Win32_SpySheriff_26{
	meta:
		description = "Rogue:Win32/SpySheriff,SIGNATURE_TYPE_PEHSTR,08 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 53 70 79 53 68 72 65 64 64 65 72 5c 53 70 79 53 68 72 65 64 64 65 72 2e 65 78 65 } //2 Program Files\SpyShredder\SpyShredder.exe
		$a_01_1 = {59 59 59 59 59 59 20 48 54 54 50 2f 31 2e 30 0d 0a 48 6f 73 74 3a 20 64 6f 77 6e 6c 6f 61 64 2e 73 70 79 2d 73 68 72 65 64 64 65 72 2e 63 6f 6d } //2
		$a_01_2 = {50 72 6f 67 72 61 6d 20 46 69 00 00 00 68 72 65 64 64 65 72 5c 53 00 00 00 65 64 64 65 72 2e 65 78 65 00 00 00 57 69 6e 64 6f 77 73 20 75 70 64 61 74 65 20 6c 6f 61 64 65 72 00 00 00 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //2
		$a_01_3 = {36 39 2e 35 30 2e 31 37 35 2e 31 38 30 00 00 00 47 45 54 20 68 74 74 70 3a 2f 2f 25 73 2f 61 73 67 68 66 64 2e 70 68 70 3f 26 26 75 3d 25 75 26 70 3d 25 75 26 6c 61 6e 67 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=6
 
}
rule Rogue_Win32_SpySheriff_27{
	meta:
		description = "Rogue:Win32/SpySheriff,SIGNATURE_TYPE_PEHSTR,53 00 52 00 0d 00 00 "
		
	strings :
		$a_01_0 = {47 65 74 4c 61 73 74 41 63 74 69 76 65 50 6f 70 75 70 } //10 GetLastActivePopup
		$a_01_1 = {4e 4f 54 49 43 45 20 54 4f 20 55 53 45 52 3a 20 20 50 4c 45 41 53 45 20 52 45 41 44 20 54 48 49 53 20 43 4f 4e 54 52 41 43 54 20 43 41 52 45 46 55 4c 4c 59 } //10 NOTICE TO USER:  PLEASE READ THIS CONTRACT CAREFULLY
		$a_01_2 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 25 73 5c 25 73 2e 6c 69 63 } //10 C:\Program Files\%s\%s.lic
		$a_01_3 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 25 73 5c 25 73 2e 65 78 65 } //10 C:\Program Files\%s\%s.exe
		$a_01_4 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 49 6e 74 65 72 6e 65 74 20 53 65 74 74 69 6e 67 73 } //10 Software\Microsoft\Windows\CurrentVersion\Internet Settings
		$a_01_5 = {50 72 6f 78 79 45 6e 61 62 6c 65 } //10 ProxyEnable
		$a_01_6 = {49 6e 74 65 72 6e 65 74 20 63 6f 6e 6e 65 63 74 69 6f 6e 20 69 73 20 75 6e 61 76 61 69 6c 61 62 6c 65 2e 20 54 72 79 20 61 67 61 69 6e 3f } //10 Internet connection is unavailable. Try again?
		$a_01_7 = {43 72 65 61 74 65 44 69 72 65 63 74 6f 72 79 41 } //10 CreateDirectoryA
		$a_01_8 = {26 61 64 76 69 64 3d } //1 &advid=
		$a_01_9 = {26 75 3d 25 75 26 70 3d 25 75 20 25 73 25 73 48 6f } //1 &u=%u&p=%u %s%sHo
		$a_01_10 = {25 73 6c 6f 61 64 2e 25 73 2e 63 6f 6d } //1 %sload.%s.com
		$a_01_11 = {73 74 3a 20 64 6f 77 6e } //1 st: down
		$a_01_12 = {25 73 43 61 63 68 65 25 73 } //1 %sCache%s
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*10+(#a_01_6  & 1)*10+(#a_01_7  & 1)*10+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1) >=82
 
}