
rule Trojan_Win32_Qakbot_GB_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 02 8b 45 c4 03 45 a4 03 45 9c 2b 45 9c 89 45 a0 8b 45 d8 8b 00 8b 55 a0 03 55 9c 2b 55 9c 2b 55 9c 03 55 9c 33 c2 89 45 a0 8b 45 a0 03 45 9c 2b 45 9c 8b 55 d8 89 02 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GB_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {8a 02 88 01 8b 4d 90 01 01 83 c1 01 89 4d 90 01 01 8b 55 90 01 01 83 c2 01 89 55 90 01 01 8b 45 90 01 01 2d 44 49 00 00 03 45 fc 2b 05 90 01 04 8b 0d 90 01 04 03 c8 89 0d 90 01 04 c7 45 90 01 01 01 00 00 00 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GB_MTB_3{
	meta:
		description = "Trojan:Win32/Qakbot.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {0f b7 f3 02 c6 02 c2 0f b6 c0 6b c0 90 01 01 2b f0 89 35 90 02 04 8a 15 90 02 04 8d 87 90 02 04 8b 7c 24 90 01 01 8a f3 80 c2 90 01 01 a3 90 02 04 02 d6 8a 35 90 02 04 89 07 83 c7 04 83 6c 24 90 01 01 01 89 7c 24 90 01 01 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GB_MTB_4{
	meta:
		description = "Trojan:Win32/Qakbot.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {0f b6 da 2b d8 83 c3 01 89 1d 90 01 04 8a c1 b3 90 01 01 f6 eb 2a c2 8a d0 83 7c 24 90 01 01 00 75 90 00 } //0a 00 
		$a_02_1 = {8b cb 6b c9 90 01 01 2b c8 2b c8 8d 4c 19 01 8b 6c 24 90 01 01 6b c0 90 01 01 81 c6 90 01 04 2b c7 89 75 00 03 c2 83 c5 04 83 6c 24 90 01 01 01 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GB_MTB_5{
	meta:
		description = "Trojan:Win32/Qakbot.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 0b 00 00 0a 00 "
		
	strings :
		$a_80_0 = {77 65 62 69 6e 6a 65 63 74 73 2e 63 62 } //webinjects.cb  01 00 
		$a_80_1 = {64 61 74 61 5f 69 6e 6a 65 63 74 } //data_inject  01 00 
		$a_80_2 = {64 61 74 61 5f 62 65 66 6f 72 65 } //data_before  01 00 
		$a_80_3 = {64 61 74 61 5f 61 66 74 65 72 } //data_after  01 00 
		$a_80_4 = {64 61 74 61 5f 65 6e 64 } //data_end  01 00 
		$a_80_5 = {70 69 64 3d 5b } //pid=[  01 00 
		$a_80_6 = {63 6f 6f 6b 69 65 3d 5b } //cookie=[  01 00 
		$a_80_7 = {65 78 65 3d 5b } //exe=[  01 00 
		$a_80_8 = {75 61 3d 5b } //ua=[  01 00 
		$a_80_9 = {25 75 2e 25 75 2e 25 75 2e 25 75 } //%u.%u.%u.%u  01 00 
		$a_80_10 = {4d 6f 7a 69 6c 6c 61 5c 46 69 72 65 66 6f 78 } //Mozilla\Firefox  00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GB_MTB_6{
	meta:
		description = "Trojan:Win32/Qakbot.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 0a 00 00 0a 00 "
		
	strings :
		$a_80_0 = {73 74 61 67 65 72 5f 31 2e 64 6c 6c } //stager_1.dll  0a 00 
		$a_80_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //DllRegisterServer  0a 00 
		$a_80_2 = {48 65 6c 6c 6f 20 71 71 71 } //Hello qqq  01 00 
		$a_80_3 = {4f 75 74 70 75 74 44 65 62 75 67 53 74 72 69 6e 67 41 } //OutputDebugStringA  01 00 
		$a_80_4 = {6d 65 6d 63 70 79 } //memcpy  01 00 
		$a_80_5 = {6d 65 6d 73 65 74 } //memset  01 00 
		$a_80_6 = {53 79 73 74 65 6d 44 72 69 76 65 } //SystemDrive  01 00 
		$a_81_7 = {55 53 45 52 50 52 4f 46 49 4c 45 } //01 00  USERPROFILE
		$a_80_8 = {43 72 65 61 74 65 50 69 70 65 } //CreatePipe  01 00 
		$a_80_9 = {47 65 74 43 75 72 72 65 6e 74 50 72 6f 63 65 73 73 } //GetCurrentProcess  00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GB_MTB_7{
	meta:
		description = "Trojan:Win32/Qakbot.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 0a 00 00 0a 00 "
		
	strings :
		$a_80_0 = {73 74 61 67 65 72 5f 31 2e 64 6c 6c } //stager_1.dll  0a 00 
		$a_80_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //DllRegisterServer  01 00 
		$a_80_2 = {68 74 74 70 73 3a 2f 2f } //https://  01 00 
		$a_80_3 = {6d 65 6d 63 70 79 } //memcpy  01 00 
		$a_80_4 = {4c 6f 6f 6b 75 70 41 63 63 6f 75 6e 74 4e 61 6d 65 57 } //LookupAccountNameW  01 00 
		$a_80_5 = {53 79 73 74 65 6d 44 72 69 76 65 } //SystemDrive  01 00 
		$a_80_6 = {6d 65 6d 73 65 74 } //memset  01 00 
		$a_80_7 = {47 65 74 55 73 65 72 50 72 6f 66 69 6c 65 44 69 72 65 63 74 6f 72 79 57 } //GetUserProfileDirectoryW  01 00 
		$a_81_8 = {55 53 45 52 50 52 4f 46 49 4c 45 } //01 00  USERPROFILE
		$a_80_9 = {4f 70 65 6e 50 72 6f 63 65 73 73 54 6f 6b 65 6e } //OpenProcessToken  00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GB_MTB_8{
	meta:
		description = "Trojan:Win32/Qakbot.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_80_0 = {62 31 39 36 62 32 38 37 2d 62 61 62 34 2d 31 30 31 61 2d 62 36 39 63 2d 30 30 61 61 30 30 33 34 31 64 30 37 } //b196b287-bab4-101a-b69c-00aa00341d07  01 00 
		$a_02_1 = {03 f0 8b 45 90 01 01 03 30 8b 4d 90 01 01 89 31 8b 55 90 01 01 8b 02 2d 90 01 02 00 00 8b 4d 90 01 01 89 01 5e 8b e5 5d c3 90 00 } //01 00 
		$a_02_2 = {8a 14 31 88 14 38 8b 45 90 01 01 83 c0 90 01 01 89 45 90 02 06 5f 5e 8b e5 5d c3 90 0a 28 00 03 45 90 01 01 8b 90 00 } //01 00 
		$a_02_3 = {8b ff 8b 0d 90 01 04 8b 15 90 01 04 89 11 90 0a ff 00 90 17 04 01 01 01 01 31 32 30 33 90 02 c8 c7 05 90 01 04 00 00 00 00 01 05 90 00 } //00 00 
		$a_00_4 = {78 c7 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_GB_MTB_9{
	meta:
		description = "Trojan:Win32/Qakbot.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {be ac 00 00 a1 90 01 04 8b 0d 90 01 04 8d 94 01 90 01 04 89 15 90 01 04 a1 90 01 04 2d be ac 00 00 a3 90 01 04 a1 90 01 04 5d c3 90 00 } //01 00 
		$a_02_1 = {03 f0 8b 45 90 01 01 03 30 8b 4d 90 01 01 89 31 8b 55 90 01 01 8b 02 2d 90 01 04 8b 4d 90 01 01 89 01 5e 8b e5 5d c3 90 00 } //01 00 
		$a_02_2 = {8a 0c 32 88 0c 38 8b 55 90 01 01 83 c2 90 01 01 89 55 90 01 01 eb 90 01 01 a1 90 01 04 a3 90 01 04 5f 5e 8b e5 5d c3 90 00 } //01 00 
		$a_02_3 = {89 08 5f 5d c3 90 0a ff 00 90 17 04 01 01 01 01 31 32 30 33 90 02 c8 c7 05 90 01 04 00 00 00 00 01 05 90 01 04 a1 90 01 04 8b 0d 90 00 } //00 00 
		$a_00_4 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}