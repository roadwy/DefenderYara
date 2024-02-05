
rule Trojan_Win32_Raccrypt_GM_MTB{
	meta:
		description = "Trojan:Win32/Raccrypt.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {b8 3b 2d 0b 00 01 45 74 8b 45 74 8a 04 08 88 04 31 41 3b 0d 90 01 04 0f 82 90 00 } //01 00 
		$a_02_1 = {33 44 24 04 c2 90 01 01 00 81 00 40 36 ef c6 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccrypt_GM_MTB_2{
	meta:
		description = "Trojan:Win32/Raccrypt.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b c8 03 d0 c1 90 01 01 04 03 45 90 01 01 c1 90 01 01 05 03 4d 90 01 01 52 89 3d 90 02 04 90 18 33 44 24 04 c2 90 01 01 00 81 00 40 36 ef c6 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccrypt_GM_MTB_3{
	meta:
		description = "Trojan:Win32/Raccrypt.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {57 66 89 15 90 01 04 c7 05 90 01 04 2e 00 64 00 c7 05 90 01 04 72 00 6e 00 c7 05 90 01 04 33 00 32 00 c7 05 90 01 04 6b 00 65 00 c7 05 90 01 04 6c 00 6c 00 a3 90 01 04 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccrypt_GM_MTB_4{
	meta:
		description = "Trojan:Win32/Raccrypt.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {25 bb 52 c0 5d 8b 90 02 14 c1 90 01 01 04 03 90 02 1e c1 90 01 01 05 03 90 02 0f 33 90 00 } //01 00 
		$a_00_1 = {33 44 24 04 c2 04 00 81 00 f5 34 ef c6 c3 } //01 00 
		$a_00_2 = {33 44 24 04 c2 04 00 81 00 f4 34 ef c6 c3 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccrypt_GM_MTB_5{
	meta:
		description = "Trojan:Win32/Raccrypt.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {b4 02 d7 cb 90 02 06 c7 05 90 01 04 ff ff ff ff 90 0a 3c 00 c1 90 01 01 04 03 90 02 04 c1 90 02 01 05 03 90 02 06 33 90 01 01 33 90 00 } //0a 00 
		$a_02_1 = {b4 02 d7 cb 90 02 06 c7 05 90 01 04 ff ff ff ff 90 0a 3c 00 c1 90 01 01 05 03 90 02 06 68 b9 79 37 9e 90 02 06 33 90 02 06 33 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccrypt_GM_MTB_6{
	meta:
		description = "Trojan:Win32/Raccrypt.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {88 55 7b 11 c7 90 02 05 8e e6 d8 1e c7 90 02 05 7b 0c db 13 c7 90 02 05 a6 c3 f8 4a c7 90 02 05 51 b7 cd 49 c7 90 02 05 29 66 56 72 c7 90 02 05 ed 90 01 02 49 c7 90 02 05 18 61 f3 05 90 00 } //01 00 
		$a_02_1 = {a5 28 36 47 c7 90 02 05 b7 e0 73 4c c7 90 02 05 02 97 13 70 c7 90 02 05 0d d2 eb 21 c7 90 02 05 05 3d e8 27 c7 90 02 05 86 38 39 19 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccrypt_GM_MTB_7{
	meta:
		description = "Trojan:Win32/Raccrypt.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {50 6a 40 ff 35 90 01 04 c6 05 90 01 04 75 ff 35 90 01 04 c6 05 90 01 04 6c c6 05 90 01 04 65 c6 05 90 01 04 63 c6 05 90 01 04 74 c6 05 90 01 04 74 c6 05 90 01 04 72 c6 05 90 01 04 69 ff 15 90 00 } //01 00 
		$a_02_1 = {f6 56 ff 35 90 01 04 66 c7 05 90 01 04 61 6c 66 c7 05 90 01 04 65 63 c6 05 90 01 04 74 66 c7 05 90 01 04 72 74 c6 05 90 01 04 75 c6 05 90 01 04 69 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}