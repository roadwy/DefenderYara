
rule Trojan_Win32_Qakbot_GA_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 02 8b 45 c4 03 45 a4 03 45 9c 2b 45 9c 89 45 a0 8b 45 a0 03 45 9c 2b 45 9c 8b 55 d8 33 02 89 45 a0 8b 45 a0 03 45 9c 2b 45 9c 8b 55 d8 89 02 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GA_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {0f b6 c1 2b c3 83 c0 90 01 01 a3 90 02 04 8b 06 05 90 02 04 89 06 83 c6 04 a3 90 02 04 0f b6 c1 66 03 05 90 02 04 66 03 c2 89 74 24 90 01 01 66 03 44 24 90 01 01 8b f2 66 03 f8 83 6c 24 90 01 01 01 66 89 7c 24 90 01 01 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GA_MTB_3{
	meta:
		description = "Trojan:Win32/Qakbot.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {8b 00 8b d9 2b 5c 24 90 01 01 05 90 01 04 52 81 c3 a6 eb 00 00 a3 90 01 04 51 89 1d 90 01 04 8b 5c 24 90 01 01 6a 00 ff 74 24 90 01 01 89 03 e8 90 01 04 8b c8 8b c3 8b 1d 90 01 04 83 c0 04 83 6c 24 90 01 01 01 89 44 24 90 01 01 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GA_MTB_4{
	meta:
		description = "Trojan:Win32/Qakbot.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 05 00 00 05 00 "
		
	strings :
		$a_00_0 = {ac 68 04 f1 07 10 c3 } //05 00 
		$a_00_1 = {34 43 68 f8 a5 08 10 c3 } //05 00 
		$a_00_2 = {68 8a d6 07 10 68 8a d6 07 10 b8 69 2c 08 10 ff d0 } //01 00 
		$a_80_3 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //VirtualProtect  01 00 
		$a_80_4 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 45 78 } //VirtualProtectEx  00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GA_MTB_5{
	meta:
		description = "Trojan:Win32/Qakbot.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {b9 40 00 00 00 90 02 04 00 ff 75 90 02 04 68 00 10 00 00 90 02 06 00 ff 75 90 02 04 57 83 90 02 02 00 31 90 02 02 ff 93 90 00 } //01 00 
		$a_02_1 = {fc f3 a4 b9 ff ff 90 02 02 ff b3 90 02 04 8f 45 90 02 02 ff 75 90 02 02 58 68 90 02 04 8f 83 90 02 04 21 8b 90 02 04 57 8b bb 90 02 04 50 8f 45 90 02 02 01 7d 90 02 02 ff 75 90 02 02 58 5f ff e0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GA_MTB_6{
	meta:
		description = "Trojan:Win32/Qakbot.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_80_0 = {62 31 39 36 62 32 38 37 2d 62 61 62 34 2d 31 30 31 61 2d 62 36 39 63 2d 30 30 61 61 30 30 33 34 31 64 30 37 } //b196b287-bab4-101a-b69c-00aa00341d07  01 00 
		$a_02_1 = {03 f0 8b 45 90 01 01 03 30 8b 4d 90 01 01 89 31 8b 55 90 01 01 8b 02 2d 90 01 02 00 00 8b 4d 90 01 01 89 01 5e 8b e5 5d c3 90 00 } //01 00 
		$a_02_2 = {8a 0c 32 88 0c 38 8b 55 90 01 01 83 c2 90 01 01 89 55 90 02 06 5f 5e 8b e5 5d c3 90 0a 28 00 03 45 90 01 01 8b 55 90 00 } //01 00 
		$a_02_3 = {8b ff 8b 0d 90 01 04 8b 15 90 01 04 89 11 90 0a ff 00 90 17 04 01 01 01 01 31 32 30 33 90 02 c8 a1 90 01 04 c7 05 90 01 04 00 00 00 00 01 05 90 00 } //00 00 
		$a_00_4 = {78 e3 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GA_MTB_7{
	meta:
		description = "Trojan:Win32/Qakbot.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1a 00 1a 00 0a 00 00 0a 00 "
		
	strings :
		$a_80_0 = {73 74 61 67 65 72 5f 31 2e 64 6c 6c } //stager_1.dll  0a 00 
		$a_80_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //DllRegisterServer  01 00 
		$a_80_2 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 41 6e 74 69 56 69 72 75 73 50 72 6f 64 75 63 74 } //SELECT * FROM AntiVirusProduct  01 00 
		$a_80_3 = {4c 6f 6f 6b 75 70 41 63 63 6f 75 6e 74 53 69 64 57 } //LookupAccountSidW  01 00 
		$a_80_4 = {4c 6f 6f 6b 75 70 41 63 63 6f 75 6e 74 4e 61 6d 65 57 } //LookupAccountNameW  01 00 
		$a_80_5 = {77 69 6e 73 74 61 30 5c 64 65 66 61 75 6c 74 } //winsta0\default  01 00 
		$a_80_6 = {6d 65 6d 73 65 74 } //memset  01 00 
		$a_80_7 = {47 65 74 55 73 65 72 50 72 6f 66 69 6c 65 44 69 72 65 63 74 6f 72 79 57 } //GetUserProfileDirectoryW  01 00 
		$a_81_8 = {55 53 45 52 50 52 4f 46 49 4c 45 } //01 00  USERPROFILE
		$a_80_9 = {4f 70 65 6e 50 72 6f 63 65 73 73 54 6f 6b 65 6e } //OpenProcessToken  00 00 
		$a_00_10 = {78 f0 00 00 16 00 16 00 07 00 00 01 00 0c 80 01 56 69 72 74 75 61 6c } //41 6c 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GA_MTB_8{
	meta:
		description = "Trojan:Win32/Qakbot.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 07 00 00 01 00 "
		
	strings :
		$a_80_0 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  01 00 
		$a_80_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  01 00 
		$a_80_2 = {62 31 39 36 62 32 38 37 2d 62 61 62 34 2d 31 30 31 61 2d 62 36 39 63 2d 30 30 61 61 30 30 33 34 31 64 30 37 } //b196b287-bab4-101a-b69c-00aa00341d07  01 00 
		$a_80_3 = {52 65 67 4f 70 65 6e 4b 65 79 41 } //RegOpenKeyA  0a 00 
		$a_02_4 = {03 f0 8b 45 90 01 01 03 30 8b 4d 90 01 01 89 31 8b 55 90 01 01 8b 02 2d bc 01 00 00 8b 4d 90 01 01 89 01 5e 8b e5 5d c3 90 00 } //0a 00 
		$a_02_5 = {8a 0c 32 88 0c 38 8b 55 90 01 01 83 c2 90 01 01 89 55 90 01 01 eb 90 01 01 5f 5e 8b e5 5d c3 90 00 } //0a 00 
		$a_02_6 = {8b ff 8b 0d 90 01 04 8b 15 90 01 04 89 11 90 0a ff 00 90 17 04 01 01 01 01 31 32 30 33 90 02 c8 a1 90 01 04 c7 05 90 01 04 00 00 00 00 01 05 90 00 } //00 00 
		$a_00_7 = {5d 04 00 00 6e 08 04 80 5c 28 00 00 6f 08 04 80 00 00 01 00 } //08 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GA_MTB_9{
	meta:
		description = "Trojan:Win32/Qakbot.GA!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {72 3a 5c 6d 64 2d 70 72 6f 6a 5c 70 72 64 79 6a 66 5c 72 74 63 33 32 2e 70 64 62 } //01 00  r:\md-proj\prdyjf\rtc32.pdb
		$a_01_1 = {d0 2d 6b 65 1c c0 d3 0b bd fd 13 89 21 41 72 eb 22 e1 79 03 b7 6d 0c 64 76 f4 3d c0 55 44 62 } //00 00 
	condition:
		any of ($a_*)
 
}