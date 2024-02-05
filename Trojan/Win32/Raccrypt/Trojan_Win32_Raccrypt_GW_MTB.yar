
rule Trojan_Win32_Raccrypt_GW_MTB{
	meta:
		description = "Trojan:Win32/Raccrypt.GW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8d 4c 24 04 90 0a 4b 00 c6 05 90 01 04 65 c6 05 90 01 04 63 c6 05 90 01 04 69 c6 05 90 01 04 75 c6 05 90 01 04 6c c6 05 90 01 04 74 c6 05 90 01 04 74 c6 05 90 01 04 72 c6 05 90 01 04 72 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccrypt_GW_MTB_2{
	meta:
		description = "Trojan:Win32/Raccrypt.GW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {81 ec 00 01 00 00 c7 90 02 06 57 78 d1 51 c7 90 02 06 0b 4c 1b 7e c7 90 02 06 dd 0b fa 64 c7 90 02 06 cf 72 b2 3d c7 90 02 06 e9 0e 74 64 c7 90 02 06 a9 53 5d 16 c7 90 02 06 05 c8 4e 43 c7 90 02 06 82 2d 68 68 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccrypt_GW_MTB_3{
	meta:
		description = "Trojan:Win32/Raccrypt.GW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {19 36 6b ff 90 0a 32 00 c1 90 01 01 04 03 90 02 0f c1 90 01 01 05 03 90 02 1e 90 17 02 01 01 31 33 90 02 14 c7 05 90 00 } //01 00 
		$a_02_1 = {19 36 6b ff 90 0a 32 00 c1 90 01 01 05 03 90 02 0f c1 90 01 01 04 03 90 02 1e 90 17 02 01 01 31 33 90 02 14 c7 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccrypt_GW_MTB_4{
	meta:
		description = "Trojan:Win32/Raccrypt.GW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 0a 00 "
		
	strings :
		$a_00_0 = {8b 44 24 04 8b 4c 24 08 31 08 c2 08 00 8b 44 24 04 8b 4c 24 08 01 08 c2 08 00 } //0a 00 
		$a_02_1 = {61 6c c6 05 90 01 04 74 66 c7 05 90 01 04 72 74 c6 05 90 01 04 75 c6 05 90 01 04 69 ff 15 90 00 } //0a 00 
		$a_02_2 = {61 6c 66 c7 05 90 02 06 c6 05 90 01 04 74 66 c7 05 90 01 04 72 74 c6 05 90 01 04 75 c6 05 90 01 04 69 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccrypt_GW_MTB_5{
	meta:
		description = "Trojan:Win32/Raccrypt.GW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {b9 65 00 00 00 ba 6e 00 00 00 b8 6b 00 00 00 68 90 01 04 c6 05 90 01 04 65 c6 05 90 01 04 72 c6 05 90 01 04 2e c6 05 90 01 04 64 c6 05 90 01 04 6c c6 05 90 01 04 00 90 00 } //01 00 
		$a_02_1 = {52 50 c6 05 90 01 04 00 c6 05 90 01 04 50 c6 05 90 01 04 61 c6 05 90 01 04 60 c6 05 90 01 04 7c c6 05 90 01 04 6f c6 05 90 01 04 74 ff 15 90 00 } //01 00 
		$a_02_2 = {51 52 c6 05 90 01 04 00 c6 05 90 01 04 50 c6 05 90 01 04 61 c6 05 90 01 04 60 c6 05 90 01 04 7c c6 05 90 01 04 6f c6 05 90 01 04 74 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Raccrypt_GW_MTB_6{
	meta:
		description = "Trojan:Win32/Raccrypt.GW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {50 6a 40 ff 90 02 14 c6 05 90 01 04 50 c6 05 90 01 04 61 c6 05 90 01 04 6f c6 05 90 01 04 74 c6 05 90 01 04 65 c6 05 90 01 04 75 c6 05 90 01 04 6c c6 05 90 01 04 69 c6 05 90 01 04 63 c6 05 90 01 04 74 c6 05 90 01 04 74 c6 05 90 01 04 72 c6 05 90 01 04 56 c6 05 90 01 04 72 ff 15 90 00 } //01 00 
		$a_02_1 = {55 8b ec 51 68 90 01 04 c6 05 90 01 04 65 c6 05 90 01 04 72 c6 05 90 01 04 2e c6 05 90 01 04 64 c6 05 90 01 04 6c c6 05 90 01 04 00 c6 05 90 01 04 65 c6 05 90 01 04 6c c6 05 90 01 04 33 c6 05 90 01 04 32 c6 05 90 01 04 6c c6 05 90 01 04 6e c6 05 90 01 04 6b ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}