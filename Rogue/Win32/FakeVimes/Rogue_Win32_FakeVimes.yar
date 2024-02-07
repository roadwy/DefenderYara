
rule Rogue_Win32_FakeVimes{
	meta:
		description = "Rogue:Win32/FakeVimes,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {6d 69 64 3d 25 73 26 77 76 3d 25 73 } //01 00  mid=%s&wv=%s
		$a_01_1 = {55 73 65 72 49 44 3d 25 73 26 77 76 3d 25 73 } //01 00  UserID=%s&wv=%s
		$a_01_2 = {69 65 78 70 6c 2a 20 2f 49 4d } //01 00  iexpl* /IM
		$a_01_3 = {68 6f 73 74 73 2e 6f 31 64 } //01 00  hosts.o1d
		$a_01_4 = {56 69 72 75 73 20 44 6f 63 74 6f 72 } //00 00  Virus Doctor
	condition:
		any of ($a_*)
 
}
rule Rogue_Win32_FakeVimes_2{
	meta:
		description = "Rogue:Win32/FakeVimes,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {54 46 61 6b 65 53 65 61 72 63 68 56 69 72 75 73 } //01 00  TFakeSearchVirus
		$a_01_1 = {46 61 6b 65 53 65 61 72 63 68 56 69 72 75 73 44 65 66 65 6e 64 65 72 55 6e 69 74 } //01 00  FakeSearchVirusDefenderUnit
		$a_01_2 = {6c 5f 4c 6f 67 6f 5f 44 65 66 65 6e 64 65 72 } //01 00  l_Logo_Defender
		$a_01_3 = {49 4e 46 45 43 54 45 44 5f 4e 41 47 } //01 00  INFECTED_NAG
		$a_01_4 = {53 50 41 4d 5f 4e 41 47 } //01 00  SPAM_NAG
		$a_01_5 = {55 50 44 41 54 45 5f 41 4c 45 52 54 5f 4e 41 47 } //00 00  UPDATE_ALERT_NAG
	condition:
		any of ($a_*)
 
}
rule Rogue_Win32_FakeVimes_3{
	meta:
		description = "Rogue:Win32/FakeVimes,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {6d 69 64 3d 25 73 26 77 76 3d 25 73 } //01 00  mid=%s&wv=%s
		$a_00_1 = {73 65 72 76 6e 2e 65 78 65 3b 77 69 6e 73 73 6b 33 32 2e 65 78 65 3b 77 69 6e 73 74 61 72 74 2e 65 78 65 3b 77 69 6e 73 74 61 72 74 30 30 31 2e 65 78 65 3b 77 69 6e 74 73 6b 33 32 2e 65 78 65 3b } //02 00  servn.exe;winssk32.exe;winstart.exe;winstart001.exe;wintsk32.exe;
		$a_00_2 = {56 69 72 75 73 44 6f 63 74 6f 72 49 6e 73 74 61 6c 6c 65 72 4d 75 74 65 78 00 } //02 00  楖畲䑳捯潴䥲獮慴汬牥畍整x
		$a_00_3 = {44 3a 5c 57 6f 72 6b 5c 41 64 77 61 72 65 50 72 6f 6a 65 63 74 73 5c 44 65 73 6b 54 6f 70 57 6f 72 6b 5c 43 6c 65 61 6e 65 72 73 5c 56 69 72 75 73 44 6f 63 74 6f 72 } //01 00  D:\Work\AdwareProjects\DeskTopWork\Cleaners\VirusDoctor
		$a_00_4 = {5c 53 79 73 46 6c 64 5c 66 61 73 74 61 76 2e 63 66 67 } //01 00  \SysFld\fastav.cfg
		$a_00_5 = {2f 72 65 70 6f 72 74 73 2f 6d 69 6e 73 74 61 6c 6c 73 2e 70 68 70 00 } //01 00 
		$a_00_6 = {72 65 70 6f 72 74 73 2f 67 65 74 5f 69 6e 73 74 61 6c 6c 5f 66 69 6c 65 2e 70 68 70 00 } //02 00 
		$a_00_7 = {63 6f 6e 74 72 6f 6c 6c 65 72 3d 6d 69 63 72 6f 69 6e 73 74 61 6c 6c 65 72 26 61 62 62 72 3d 25 73 } //00 00  controller=microinstaller&abbr=%s
	condition:
		any of ($a_*)
 
}
rule Rogue_Win32_FakeVimes_4{
	meta:
		description = "Rogue:Win32/FakeVimes,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 18 00 00 ffffff9c ffffffff "
		
	strings :
		$a_01_0 = {4f 2d 4b 65 79 20 44 6f 6e 67 6c 65 7c 4f 42 54 } //02 00  O-Key Dongle|OBT
		$a_03_1 = {8b 47 3c 03 c7 89 45 90 01 01 6a 04 68 00 30 00 00 8b 45 90 1b 00 8b 40 50 50 8b 45 90 1b 00 e8 90 00 } //02 00 
		$a_03_2 = {8b 40 3c 03 45 90 01 01 89 45 90 01 01 6a 01 68 00 20 00 00 8b 45 90 1b 01 8b 40 50 50 53 e8 90 00 } //02 00 
		$a_03_3 = {6a 40 68 00 30 00 00 90 02 09 8b 90 01 01 50 50 90 02 09 8b 90 01 01 34 50 8b 45 90 01 01 50 90 17 03 02 01 08 ff 15 e8 a1 90 01 04 8b 00 ff d0 90 00 } //02 00 
		$a_03_4 = {6a 40 68 00 30 00 00 51 52 50 ff 15 90 01 04 c3 90 09 06 00 90 02 05 90 03 01 01 c2 c3 90 00 } //02 00 
		$a_03_5 = {0f b7 40 06 48 85 c0 90 03 01 01 72 7c 90 01 01 40 89 45 90 01 01 33 db 8d 90 03 0d 09 45 90 01 01 50 8d 34 9b 8b 45 90 01 01 04 9b 8b 7c c6 08 8d 04 9b 8b 44 90 03 01 01 f0 c6 10 90 00 } //02 00 
		$a_03_6 = {32 c1 8b 4d f8 8b 7d 90 01 01 0f b6 4c 39 ff 03 c9 c1 e9 02 32 c1 32 d0 88 55 ef 90 00 } //01 00 
		$a_03_7 = {8b 40 28 03 45 90 09 03 00 8b 45 90 01 07 90 04 01 02 a3 89 90 00 } //01 00 
		$a_01_8 = {5e 57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 5e 56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 5e 56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 45 78 5e 5a 77 55 6e 6d 61 70 56 69 65 77 4f 66 53 65 63 74 69 6f 6e 5e 52 65 61 64 50 72 6f 63 } //01 00  ^WriteProcessMemory^VirtualAllocEx^VirtualProtectEx^ZwUnmapViewOfSection^ReadProc
		$a_00_9 = {85 c9 74 19 8b 41 01 80 39 e9 74 0c 80 39 eb 75 0c 0f be c0 41 41 eb 03 83 c1 05 01 c1 } //02 00 
		$a_03_10 = {8b 47 28 03 45 90 01 01 8b 55 90 01 01 89 82 b0 00 00 00 8b 45 90 01 01 50 8b 45 90 01 01 50 90 03 01 08 e8 a1 90 01 04 8b 00 ff d0 90 00 } //02 00 
		$a_03_11 = {8b 47 28 03 45 90 01 01 89 83 b0 00 00 00 90 00 } //02 00 
		$a_01_12 = {03 43 28 89 86 b0 00 00 00 } //02 00 
		$a_03_13 = {89 87 b0 00 00 00 90 09 06 00 90 03 09 06 8b 90 01 02 03 90 01 01 28 8b 90 01 01 28 03 90 00 } //02 00 
		$a_03_14 = {89 b0 b0 00 00 00 90 09 18 00 90 02 0f 8b 45 90 02 10 03 47 28 90 02 0f 8b 45 90 00 } //01 00 
		$a_03_15 = {07 00 01 00 90 09 02 00 c7 90 00 } //01 00 
		$a_03_16 = {06 48 66 85 c0 90 03 04 05 72 90 01 01 0f 82 90 01 04 40 66 89 90 09 08 00 66 8b 90 00 } //01 00 
		$a_03_17 = {8b 40 3c 8b 90 01 01 03 c2 05 f8 00 00 00 90 00 } //01 00 
		$a_01_18 = {8b 40 3c 03 c3 05 f8 00 00 00 } //01 00 
		$a_03_19 = {66 8b 7b 06 4f 66 85 ff 72 90 01 01 47 33 90 00 } //01 00 
		$a_01_20 = {8b 58 3c 03 de 81 c3 f8 00 00 00 } //01 00 
		$a_03_21 = {68 f8 00 00 00 56 8b 45 90 01 01 8b 40 3c 03 90 01 01 50 90 00 } //01 00 
		$a_03_22 = {68 f8 00 00 00 8b 45 90 01 01 50 8b c3 03 46 3c 50 90 00 } //01 00 
		$a_03_23 = {d1 e0 03 42 24 03 45 0c 66 8b 00 90 02 20 25 ff ff 00 00 c1 e0 02 03 42 1c 90 02 09 03 45 0c 90 02 09 8b 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Rogue_Win32_FakeVimes_5{
	meta:
		description = "Rogue:Win32/FakeVimes,SIGNATURE_TYPE_PEHSTR,05 00 05 00 08 00 00 02 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 72 65 70 6f 72 74 63 6f 75 6e 74 64 6f 6d 6e 65 74 } //01 00  httpreportcountdomnet
		$a_01_1 = {56 69 72 75 73 44 6f 63 74 6f 72 49 6e 73 74 61 6c 6c 65 72 4d 75 74 65 78 } //01 00  VirusDoctorInstallerMutex
		$a_01_2 = {41 64 77 61 72 65 50 72 6f 6a 65 63 74 73 5c 44 65 73 6b 54 6f 70 57 6f 72 6b 5c 43 6c 65 61 6e 65 72 73 5c 56 69 72 75 73 44 6f 63 74 6f 72 } //01 00  AdwareProjects\DeskTopWork\Cleaners\VirusDoctor
		$a_01_3 = {6f 70 65 6e 74 61 73 6b 6b 69 6c 6c 65 78 65 } //01 00  opentaskkillexe
		$a_01_4 = {61 6e 74 69 74 72 6f 6a 61 6e 65 78 65 61 6e 74 69 76 69 72 75 73 65 78 65 61 6e 74 73 65 78 65 61 70 69 6d 6f 6e 69 74 6f 72 65 78 65 61 70 6c 69 63 61 65 78 65 61 70 76 78 64 77 69 6e 65 78 65 } //01 00  antitrojanexeantivirusexeantsexeapimonitorexeaplicaexeapvxdwinexe
		$a_01_5 = {53 4d 41 52 54 5f 49 4e 54 45 52 4e 45 54 5f 50 52 4f 54 45 43 54 49 4f 4e 5f 5f 55 4e 49 4e 53 54 41 4c 4c 53 6d 61 72 74 49 50 65 78 65 53 4d 41 52 54 5f 49 4e 54 45 52 4e 45 54 5f 50 52 4f 54 45 43 54 49 4f 4e 5f 5f 41 50 50 } //01 00  SMART_INTERNET_PROTECTION__UNINSTALLSmartIPexeSMART_INTERNET_PROTECTION__APP
		$a_01_6 = {69 66 65 78 69 73 74 73 67 6f 74 6f 52 65 70 65 61 74 64 65 6c 73 52 65 70 65 61 74 64 65 6c 62 61 74 } //01 00  ifexistsgotoRepeatdelsRepeatdelbat
		$a_01_7 = {67 65 74 5f 69 6e 73 74 61 6c 6c 5f 66 69 6c 65 70 68 70 69 6e 64 65 78 70 68 70 } //00 00  get_install_filephpindexphp
	condition:
		any of ($a_*)
 
}