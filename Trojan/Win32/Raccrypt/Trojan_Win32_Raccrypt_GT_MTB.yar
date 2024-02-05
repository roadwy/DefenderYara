
rule Trojan_Win32_Raccrypt_GT_MTB{
	meta:
		description = "Trojan:Win32/Raccrypt.GT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {c1 e8 05 89 44 24 90 01 01 90 02 04 8b 90 01 01 24 90 01 01 33 90 01 01 24 90 01 01 03 90 01 01 24 90 01 01 c7 05 90 01 04 ee 3d ea f4 33 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccrypt_GT_MTB_2{
	meta:
		description = "Trojan:Win32/Raccrypt.GT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {30 04 0a 81 bc 24 90 01 04 91 05 00 00 90 18 41 3b 8c 24 90 01 04 89 4c 24 90 01 01 0f 8c 90 00 } //01 00 
		$a_02_1 = {91 05 00 00 75 56 90 0a 14 00 8b 4c 24 90 01 01 30 04 90 01 01 81 bc 24 90 01 02 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccrypt_GT_MTB_3{
	meta:
		description = "Trojan:Win32/Raccrypt.GT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {6a 00 ff 15 90 0a 72 00 c6 05 90 01 04 50 c6 05 90 01 04 61 c6 05 90 01 04 65 c6 05 90 01 04 6c c6 05 90 01 04 69 c6 05 90 01 04 75 c6 05 90 01 04 63 c6 05 90 01 04 74 c6 05 90 01 04 74 c6 05 90 01 04 72 c6 05 90 01 04 72 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccrypt_GT_MTB_4{
	meta:
		description = "Trojan:Win32/Raccrypt.GT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {3b 2d 0b 00 8b 0d 90 01 04 88 04 90 01 01 75 90 00 } //01 00 
		$a_02_1 = {25 bb 52 c0 5d 8b 90 02 06 8b 90 02 04 c1 90 01 01 04 03 90 02 08 c1 90 02 01 05 03 90 02 28 8b 45 90 01 01 29 45 90 01 01 81 90 01 01 47 86 c8 61 90 02 05 0f 85 90 00 } //01 00 
		$a_00_2 = {33 44 24 04 c2 04 00 81 00 a4 36 ef c6 c3 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccrypt_GT_MTB_5{
	meta:
		description = "Trojan:Win32/Raccrypt.GT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {5e aa cd 04 c7 90 02 05 d2 a3 3a 6a c7 90 02 05 68 3f 01 6b c7 90 02 05 3f 5d 8e 10 c7 90 02 05 5b fd 46 4a c7 90 02 05 d7 99 ac 7c c7 90 02 05 b5 0d 96 5f c7 90 02 05 b3 6b 51 02 c7 90 02 05 65 51 93 0b c7 90 02 05 8b 68 36 7d c7 90 02 05 32 a9 23 7a c7 90 02 05 00 2b 5a 11 c7 90 02 05 b9 af 00 62 c7 90 02 05 4e 0b 44 74 c7 90 02 05 12 65 93 01 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccrypt_GT_MTB_6{
	meta:
		description = "Trojan:Win32/Raccrypt.GT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0a 00 03 00 00 0a 00 "
		
	strings :
		$a_02_0 = {47 00 65 c6 05 90 01 04 50 c6 05 90 01 04 00 c6 05 90 01 05 c6 05 90 01 04 63 c6 05 90 01 04 61 c6 05 90 01 04 74 c6 05 90 01 04 72 c6 05 90 01 04 75 90 00 } //02 00 
		$a_00_1 = {6b 00 65 00 72 00 6e 00 65 00 6c 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 } //02 00 
		$a_02_2 = {b8 36 23 01 00 01 45 90 01 01 8b 15 90 01 04 03 55 90 01 01 8b 45 90 01 01 03 45 90 01 01 8a 08 88 0a 8b e5 5d c2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccrypt_GT_MTB_7{
	meta:
		description = "Trojan:Win32/Raccrypt.GT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {36 dd 96 53 81 45 90 01 01 3a dd 96 53 8b 90 02 1e c1 90 01 01 05 03 90 02 14 33 90 00 } //01 00 
		$a_02_1 = {36 dd 96 53 81 45 90 01 01 3a dd 96 53 8b 90 02 1e c1 90 01 01 05 03 90 02 14 31 90 00 } //01 00 
		$a_02_2 = {36 dd 96 53 81 45 90 01 01 3a dd 96 53 8b 90 02 1e c1 90 01 01 05 03 90 0a 14 00 33 90 00 } //01 00 
		$a_02_3 = {36 dd 96 53 81 45 90 01 01 3a dd 96 53 8b 90 02 1e c1 90 01 01 05 03 90 0a 14 00 31 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccrypt_GT_MTB_8{
	meta:
		description = "Trojan:Win32/Raccrypt.GT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {36 dd 96 53 81 45 90 01 01 3a dd 96 53 8b 90 02 1e c1 90 01 01 05 89 90 02 28 33 90 00 } //01 00 
		$a_02_1 = {36 dd 96 53 81 45 90 01 01 3a dd 96 53 8b 90 02 1e c1 90 01 01 05 89 90 02 28 31 90 00 } //01 00 
		$a_02_2 = {36 dd 96 53 81 45 90 01 01 3a dd 96 53 8b 90 02 1e c1 90 01 01 05 89 90 0a 28 00 33 90 00 } //01 00 
		$a_02_3 = {36 dd 96 53 81 45 90 01 01 3a dd 96 53 8b 90 02 1e c1 90 01 01 05 89 90 0a 28 00 31 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccrypt_GT_MTB_9{
	meta:
		description = "Trojan:Win32/Raccrypt.GT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 0a 00 "
		
	strings :
		$a_02_0 = {65 63 c6 05 90 01 04 74 66 c7 05 90 01 04 61 6c c6 05 90 01 04 74 66 c7 05 90 01 04 72 74 c6 05 90 01 04 75 c6 05 90 01 04 69 ff 15 90 00 } //0a 00 
		$a_00_1 = {8b 44 24 04 8b 4c 24 08 31 08 c2 08 00 8b 44 24 04 8b 4c 24 08 01 08 c2 08 00 8b 44 24 08 8b 4c 24 04 c1 e0 04 89 01 c2 08 00 } //0a 00 
		$a_02_2 = {b4 21 e1 c5 90 02 05 e8 90 01 04 8b 90 02 03 29 90 02 05 81 90 02 02 47 86 c8 61 ff 90 02 05 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}