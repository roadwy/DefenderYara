
rule Trojan_Win32_Qakbot_GA_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 02 8b 45 c4 03 45 a4 03 45 9c 2b 45 9c 89 45 a0 8b 45 a0 03 45 9c 2b 45 9c 8b 55 d8 33 02 89 45 a0 8b 45 a0 03 45 9c 2b 45 9c 8b 55 d8 89 02 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qakbot_GA_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 c1 2b c3 83 c0 ?? a3 [0-04] 8b 06 05 [0-04] 89 06 83 c6 04 a3 [0-04] 0f b6 c1 66 03 05 [0-04] 66 03 c2 89 74 24 ?? 66 03 44 24 ?? 8b f2 66 03 f8 83 6c 24 ?? 01 66 89 7c 24 ?? 0f 85 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Qakbot_GA_MTB_3{
	meta:
		description = "Trojan:Win32/Qakbot.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 00 8b d9 2b 5c 24 ?? 05 ?? ?? ?? ?? 52 81 c3 a6 eb 00 00 a3 ?? ?? ?? ?? 51 89 1d ?? ?? ?? ?? 8b 5c 24 ?? 6a 00 ff 74 24 ?? 89 03 e8 ?? ?? ?? ?? 8b c8 8b c3 8b 1d ?? ?? ?? ?? 83 c0 04 83 6c 24 ?? 01 89 44 24 ?? 75 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Qakbot_GA_MTB_4{
	meta:
		description = "Trojan:Win32/Qakbot.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 05 00 00 "
		
	strings :
		$a_00_0 = {ac 68 04 f1 07 10 c3 } //5
		$a_00_1 = {34 43 68 f8 a5 08 10 c3 } //5
		$a_00_2 = {68 8a d6 07 10 68 8a d6 07 10 b8 69 2c 08 10 ff d0 } //5
		$a_80_3 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //VirtualProtect  1
		$a_80_4 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 45 78 } //VirtualProtectEx  1
	condition:
		((#a_00_0  & 1)*5+(#a_00_1  & 1)*5+(#a_00_2  & 1)*5+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=16
 
}
rule Trojan_Win32_Qakbot_GA_MTB_5{
	meta:
		description = "Trojan:Win32/Qakbot.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {b9 40 00 00 00 [0-04] 00 ff 75 [0-04] 68 00 10 00 00 [0-06] 00 ff 75 [0-04] 57 83 [0-02] 00 31 [0-02] ff 93 } //1
		$a_02_1 = {fc f3 a4 b9 ff ff [0-02] ff b3 [0-04] 8f 45 [0-02] ff 75 [0-02] 58 68 [0-04] 8f 83 [0-04] 21 8b [0-04] 57 8b bb [0-04] 50 8f 45 [0-02] 01 7d [0-02] ff 75 [0-02] 58 5f ff e0 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Qakbot_GA_MTB_6{
	meta:
		description = "Trojan:Win32/Qakbot.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_80_0 = {62 31 39 36 62 32 38 37 2d 62 61 62 34 2d 31 30 31 61 2d 62 36 39 63 2d 30 30 61 61 30 30 33 34 31 64 30 37 } //b196b287-bab4-101a-b69c-00aa00341d07  1
		$a_02_1 = {03 f0 8b 45 ?? 03 30 8b 4d ?? 89 31 8b 55 ?? 8b 02 2d ?? ?? 00 00 8b 4d ?? 89 01 5e 8b e5 5d c3 } //1
		$a_02_2 = {8a 0c 32 88 0c 38 8b 55 ?? 83 c2 ?? 89 55 [0-06] 5f 5e 8b e5 5d c3 90 0a 28 00 03 45 ?? 8b 55 } //1
		$a_02_3 = {8b ff 8b 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 11 90 0a ff 00 90 17 04 01 01 01 01 31 32 30 33 [0-c8] a1 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 00 00 00 00 01 05 } //1
	condition:
		((#a_80_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1) >=3
 
}
rule Trojan_Win32_Qakbot_GA_MTB_7{
	meta:
		description = "Trojan:Win32/Qakbot.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1a 00 1a 00 0a 00 00 "
		
	strings :
		$a_80_0 = {73 74 61 67 65 72 5f 31 2e 64 6c 6c } //stager_1.dll  10
		$a_80_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //DllRegisterServer  10
		$a_80_2 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 41 6e 74 69 56 69 72 75 73 50 72 6f 64 75 63 74 } //SELECT * FROM AntiVirusProduct  1
		$a_80_3 = {4c 6f 6f 6b 75 70 41 63 63 6f 75 6e 74 53 69 64 57 } //LookupAccountSidW  1
		$a_80_4 = {4c 6f 6f 6b 75 70 41 63 63 6f 75 6e 74 4e 61 6d 65 57 } //LookupAccountNameW  1
		$a_80_5 = {77 69 6e 73 74 61 30 5c 64 65 66 61 75 6c 74 } //winsta0\default  1
		$a_80_6 = {6d 65 6d 73 65 74 } //memset  1
		$a_80_7 = {47 65 74 55 73 65 72 50 72 6f 66 69 6c 65 44 69 72 65 63 74 6f 72 79 57 } //GetUserProfileDirectoryW  1
		$a_81_8 = {55 53 45 52 50 52 4f 46 49 4c 45 } //1 USERPROFILE
		$a_80_9 = {4f 70 65 6e 50 72 6f 63 65 73 73 54 6f 6b 65 6e } //OpenProcessToken  1
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*10+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_81_8  & 1)*1+(#a_80_9  & 1)*1) >=26
 
}
rule Trojan_Win32_Qakbot_GA_MTB_8{
	meta:
		description = "Trojan:Win32/Qakbot.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 07 00 00 "
		
	strings :
		$a_80_0 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  1
		$a_80_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  1
		$a_80_2 = {62 31 39 36 62 32 38 37 2d 62 61 62 34 2d 31 30 31 61 2d 62 36 39 63 2d 30 30 61 61 30 30 33 34 31 64 30 37 } //b196b287-bab4-101a-b69c-00aa00341d07  1
		$a_80_3 = {52 65 67 4f 70 65 6e 4b 65 79 41 } //RegOpenKeyA  1
		$a_02_4 = {03 f0 8b 45 ?? 03 30 8b 4d ?? 89 31 8b 55 ?? 8b 02 2d bc 01 00 00 8b 4d ?? 89 01 5e 8b e5 5d c3 } //10
		$a_02_5 = {8a 0c 32 88 0c 38 8b 55 ?? 83 c2 ?? 89 55 ?? eb ?? 5f 5e 8b e5 5d c3 } //10
		$a_02_6 = {8b ff 8b 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 11 90 0a ff 00 90 17 04 01 01 01 01 31 32 30 33 [0-c8] a1 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 00 00 00 00 01 05 } //10
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_02_4  & 1)*10+(#a_02_5  & 1)*10+(#a_02_6  & 1)*10) >=22
 
}
rule Trojan_Win32_Qakbot_GA_MTB_9{
	meta:
		description = "Trojan:Win32/Qakbot.GA!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {72 3a 5c 6d 64 2d 70 72 6f 6a 5c 70 72 64 79 6a 66 5c 72 74 63 33 32 2e 70 64 62 } //1 r:\md-proj\prdyjf\rtc32.pdb
		$a_01_1 = {d0 2d 6b 65 1c c0 d3 0b bd fd 13 89 21 41 72 eb 22 e1 79 03 b7 6d 0c 64 76 f4 3d c0 55 44 62 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}