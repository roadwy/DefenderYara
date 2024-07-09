
rule Trojan_Win32_Raccrypt_GT_MTB{
	meta:
		description = "Trojan:Win32/Raccrypt.GT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 e8 05 89 44 24 ?? [0-04] 8b ?? 24 ?? 33 ?? 24 ?? 03 ?? 24 ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 33 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccrypt_GT_MTB_2{
	meta:
		description = "Trojan:Win32/Raccrypt.GT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {30 04 0a 81 bc 24 ?? ?? ?? ?? 91 05 00 00 90 18 41 3b 8c 24 ?? ?? ?? ?? 89 4c 24 ?? 0f 8c } //1
		$a_02_1 = {91 05 00 00 75 56 90 0a 14 00 8b 4c 24 ?? 30 04 ?? 81 bc 24 ?? ?? 00 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccrypt_GT_MTB_3{
	meta:
		description = "Trojan:Win32/Raccrypt.GT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {6a 00 ff 15 90 0a 72 00 c6 05 ?? ?? ?? ?? 50 c6 05 ?? ?? ?? ?? 61 c6 05 ?? ?? ?? ?? 65 c6 05 ?? ?? ?? ?? 6c c6 05 ?? ?? ?? ?? 69 c6 05 ?? ?? ?? ?? 75 c6 05 ?? ?? ?? ?? 63 c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 72 c6 05 ?? ?? ?? ?? 72 c3 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccrypt_GT_MTB_4{
	meta:
		description = "Trojan:Win32/Raccrypt.GT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_02_0 = {3b 2d 0b 00 8b 0d ?? ?? ?? ?? 88 04 ?? 75 } //1
		$a_02_1 = {25 bb 52 c0 5d 8b [0-06] 8b [0-04] c1 ?? 04 03 [0-08] c1 [0-01] 05 03 [0-28] 8b 45 ?? 29 45 ?? 81 ?? 47 86 c8 61 [0-05] 0f 85 } //1
		$a_00_2 = {33 44 24 04 c2 04 00 81 00 a4 36 ef c6 c3 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1) >=2
 
}
rule Trojan_Win32_Raccrypt_GT_MTB_5{
	meta:
		description = "Trojan:Win32/Raccrypt.GT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {5e aa cd 04 c7 [0-05] d2 a3 3a 6a c7 [0-05] 68 3f 01 6b c7 [0-05] 3f 5d 8e 10 c7 [0-05] 5b fd 46 4a c7 [0-05] d7 99 ac 7c c7 [0-05] b5 0d 96 5f c7 [0-05] b3 6b 51 02 c7 [0-05] 65 51 93 0b c7 [0-05] 8b 68 36 7d c7 [0-05] 32 a9 23 7a c7 [0-05] 00 2b 5a 11 c7 [0-05] b9 af 00 62 c7 [0-05] 4e 0b 44 74 c7 [0-05] 12 65 93 01 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccrypt_GT_MTB_6{
	meta:
		description = "Trojan:Win32/Raccrypt.GT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0a 00 03 00 00 "
		
	strings :
		$a_02_0 = {47 00 65 c6 05 ?? ?? ?? ?? 50 c6 05 ?? ?? ?? ?? 00 c6 05 ?? ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 63 c6 05 ?? ?? ?? ?? 61 c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 72 c6 05 ?? ?? ?? ?? 75 } //10
		$a_00_1 = {6b 00 65 00 72 00 6e 00 65 00 6c 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 } //2 kernel32.dll
		$a_02_2 = {b8 36 23 01 00 01 45 ?? 8b 15 ?? ?? ?? ?? 03 55 ?? 8b 45 ?? 03 45 ?? 8a 08 88 0a 8b e5 5d c2 } //2
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*2+(#a_02_2  & 1)*2) >=10
 
}
rule Trojan_Win32_Raccrypt_GT_MTB_7{
	meta:
		description = "Trojan:Win32/Raccrypt.GT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_02_0 = {36 dd 96 53 81 45 ?? 3a dd 96 53 8b [0-1e] c1 ?? 05 03 [0-14] 33 } //1
		$a_02_1 = {36 dd 96 53 81 45 ?? 3a dd 96 53 8b [0-1e] c1 ?? 05 03 [0-14] 31 } //1
		$a_02_2 = {36 dd 96 53 81 45 ?? 3a dd 96 53 8b [0-1e] c1 ?? 05 03 90 0a 14 00 33 } //1
		$a_02_3 = {36 dd 96 53 81 45 ?? 3a dd 96 53 8b [0-1e] c1 ?? 05 03 90 0a 14 00 31 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccrypt_GT_MTB_8{
	meta:
		description = "Trojan:Win32/Raccrypt.GT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_02_0 = {36 dd 96 53 81 45 ?? 3a dd 96 53 8b [0-1e] c1 ?? 05 89 [0-28] 33 } //1
		$a_02_1 = {36 dd 96 53 81 45 ?? 3a dd 96 53 8b [0-1e] c1 ?? 05 89 [0-28] 31 } //1
		$a_02_2 = {36 dd 96 53 81 45 ?? 3a dd 96 53 8b [0-1e] c1 ?? 05 89 90 0a 28 00 33 } //1
		$a_02_3 = {36 dd 96 53 81 45 ?? 3a dd 96 53 8b [0-1e] c1 ?? 05 89 90 0a 28 00 31 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1) >=1
 
}
rule Trojan_Win32_Raccrypt_GT_MTB_9{
	meta:
		description = "Trojan:Win32/Raccrypt.GT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_02_0 = {65 63 c6 05 ?? ?? ?? ?? 74 66 c7 05 ?? ?? ?? ?? 61 6c c6 05 ?? ?? ?? ?? 74 66 c7 05 ?? ?? ?? ?? 72 74 c6 05 ?? ?? ?? ?? 75 c6 05 ?? ?? ?? ?? 69 ff 15 } //10
		$a_00_1 = {8b 44 24 04 8b 4c 24 08 31 08 c2 08 00 8b 44 24 04 8b 4c 24 08 01 08 c2 08 00 8b 44 24 08 8b 4c 24 04 c1 e0 04 89 01 c2 08 00 } //10
		$a_02_2 = {b4 21 e1 c5 [0-05] e8 ?? ?? ?? ?? 8b [0-03] 29 [0-05] 81 [0-02] 47 86 c8 61 ff [0-05] 75 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*10+(#a_02_2  & 1)*10) >=10
 
}