
rule Trojan_Win32_Raccrypt_GY_MTB{
	meta:
		description = "Trojan:Win32/Raccrypt.GY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {25 bb 52 c0 5d 8b [0-0a] c1 ?? 04 03 [0-19] c1 [0-01] 05 03 [0-0a] 90 17 02 01 01 31 33 [0-14] 0f 85 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccrypt_GY_MTB_2{
	meta:
		description = "Trojan:Win32/Raccrypt.GY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8f fb 24 5e c7 85 ?? ?? ?? ?? 76 96 cc 13 c7 85 ?? ?? ?? ?? 68 e3 5c 14 c7 85 ?? ?? ?? ?? aa e4 a4 53 c7 85 ?? ?? ?? ?? cc 54 04 18 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccrypt_GY_MTB_3{
	meta:
		description = "Trojan:Win32/Raccrypt.GY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {23 29 9b 47 c7 85 ?? ?? ?? ?? 06 80 e6 6a c7 85 ?? ?? ?? ?? 07 b5 1f 11 c7 85 ?? ?? ?? ?? c8 cc 51 4b c7 85 ?? ?? ?? ?? 82 1b a6 1f c7 85 ?? ?? ?? ?? c9 ba ac 1b c7 85 ?? ?? ?? ?? d6 f7 22 3f } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccrypt_GY_MTB_4{
	meta:
		description = "Trojan:Win32/Raccrypt.GY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {21 e8 46 32 c7 85 ?? ?? ?? ?? 25 bd b1 77 c7 85 ?? ?? ?? ?? d3 29 2d 6c c7 85 ?? ?? ?? ?? a2 b9 cd 19 c7 85 ?? ?? ?? ?? fb d0 9d 68 c7 85 ?? ?? ?? ?? dc c0 69 54 c7 85 ?? ?? ?? ?? 98 c3 e4 01 c7 85 ?? ?? ?? ?? be 14 4a 0a } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccrypt_GY_MTB_5{
	meta:
		description = "Trojan:Win32/Raccrypt.GY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {55 8b ec b8 90 0a 6e 00 c6 05 ?? ?? ?? ?? 50 c6 05 ?? ?? ?? ?? 61 c6 05 ?? ?? ?? ?? 65 c6 05 ?? ?? ?? ?? 6c c6 05 ?? ?? ?? ?? 69 c6 05 ?? ?? ?? ?? 75 c6 05 ?? ?? ?? ?? 63 c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 72 c6 05 ?? ?? ?? ?? 72 c3 c3 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccrypt_GY_MTB_6{
	meta:
		description = "Trojan:Win32/Raccrypt.GY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {58 6a 72 66 a3 ?? ?? ?? ?? 58 6a 6c 66 a3 ?? ?? ?? ?? 58 6a 32 66 a3 ?? ?? ?? ?? 58 6a 2e 66 a3 ?? ?? ?? ?? 58 6a 6e 66 a3 ?? ?? ?? ?? 58 6a 65 66 a3 ?? ?? ?? ?? 58 6a 64 66 a3 ?? ?? ?? ?? 58 6a 33 66 a3 ?? ?? ?? ?? 58 6a 65 66 a3 ?? ?? ?? ?? 58 68 ?? ?? ?? ?? 66 a3 ?? ?? ?? ?? ff 15 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccrypt_GY_MTB_7{
	meta:
		description = "Trojan:Win32/Raccrypt.GY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_02_0 = {c7 45 f8 40 00 00 00 [0-07] c6 05 ?? ?? ?? ?? 65 c6 05 ?? ?? ?? ?? 50 c6 05 ?? ?? ?? ?? 00 c6 05 ?? ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 63 c6 05 ?? ?? ?? ?? 61 c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 72 } //10
		$a_00_1 = {6b 00 65 00 72 00 6e 00 65 00 6c 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 } //1 kernel32.dll
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*1) >=11
 
}
rule Trojan_Win32_Raccrypt_GY_MTB_8{
	meta:
		description = "Trojan:Win32/Raccrypt.GY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {6a 00 c7 05 ?? ?? ?? ?? 64 00 6c 00 c7 05 ?? ?? ?? ?? 72 00 6e 00 c7 05 ?? ?? ?? ?? 6b 00 65 00 c7 05 ?? ?? ?? ?? 33 00 32 00 c7 05 ?? ?? ?? ?? 6c 00 00 00 } //1
		$a_02_1 = {74 00 c7 05 ?? ?? ?? ?? 56 69 72 74 c7 05 ?? ?? ?? ?? 75 61 6c 50 c7 05 ?? ?? ?? ?? 72 6f 74 65 c6 05 ?? ?? ?? ?? 63 ff 15 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccrypt_GY_MTB_9{
	meta:
		description = "Trojan:Win32/Raccrypt.GY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_02_0 = {6c 66 c7 05 ?? ?? ?? ?? 65 63 c6 05 ?? ?? ?? ?? 74 66 c7 05 ?? ?? ?? ?? 72 74 c6 05 ?? ?? ?? ?? 75 c6 05 ?? ?? ?? ?? 69 ff 15 } //10
		$a_02_1 = {f6 56 ff 35 ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 6c c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 65 c6 05 ?? ?? ?? ?? 63 c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 72 c6 05 ?? ?? ?? ?? 75 c6 05 ?? ?? ?? ?? 69 ff 15 } //10
		$a_02_2 = {81 ec 2c 05 00 00 56 c6 05 ?? ?? ?? ?? 6b c6 05 ?? ?? ?? ?? 65 c6 05 ?? ?? ?? ?? 72 c6 05 ?? ?? ?? ?? 2e c6 05 ?? ?? ?? ?? 64 c6 05 ?? ?? ?? ?? 6c c6 05 ?? ?? ?? ?? 00 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_02_2  & 1)*10) >=10
 
}