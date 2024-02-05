
rule Trojan_Win32_AveMaria_PVD_MTB{
	meta:
		description = "Trojan:Win32/AveMaria.PVD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 05 00 00 02 00 "
		
	strings :
		$a_02_0 = {8b 44 24 1c 81 c3 47 86 c8 61 ff 4c 24 20 8b 4c 24 18 89 5c 24 14 0f 85 90 09 06 00 8b 35 90 00 } //02 00 
		$a_02_1 = {8a c1 81 c7 f8 d7 fa 01 02 c0 89 3d 90 01 04 02 c8 8a 44 24 13 f6 d8 c0 e1 02 2a c1 a2 90 01 04 8b 44 24 28 89 38 90 09 06 00 89 35 90 00 } //02 00 
		$a_00_2 = {8b 45 f4 0f b6 0c 10 8b 55 f8 0f b6 84 15 d8 d5 ff ff 33 c1 8b 4d f8 88 84 0d d8 d5 ff ff } //01 00 
		$a_02_3 = {8a 0c 32 8b 15 90 01 04 88 0c 32 8b 4c 24 30 8a 54 01 ff 88 54 24 08 8b 4c 24 08 90 00 } //01 00 
		$a_02_4 = {8a 4c 24 14 a3 90 01 04 a1 90 01 04 30 0c 18 8b c6 5b 5e c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}