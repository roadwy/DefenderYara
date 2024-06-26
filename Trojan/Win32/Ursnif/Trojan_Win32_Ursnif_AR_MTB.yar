
rule Trojan_Win32_Ursnif_AR_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 02 39 7c 24 18 72 90 02 04 02 cd 05 54 a0 09 01 83 c6 04 89 02 90 02 2f 81 fe 90 01 04 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ursnif_AR_MTB_2{
	meta:
		description = "Trojan:Win32/Ursnif.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {2b de 89 54 24 90 01 01 81 c3 90 01 04 89 15 90 01 04 89 10 90 08 50 00 6b 7c 24 90 01 02 8b 35 90 01 04 83 44 24 90 01 02 f7 de 2b f7 8b 7c 24 90 01 01 66 03 de 90 00 } //01 00 
		$a_02_1 = {8d 04 c9 0f b7 d1 2b 44 24 90 01 01 81 c6 90 01 04 66 03 f8 89 74 24 90 01 01 8b 44 24 90 01 01 89 35 90 01 04 89 54 24 90 01 01 66 89 3d 90 01 04 89 30 8b f3 81 c6 90 01 04 8b c5 83 d0 90 01 01 89 44 24 90 01 01 8b c2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ursnif_AR_MTB_3{
	meta:
		description = "Trojan:Win32/Ursnif.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0c 00 00 0a 00 "
		
	strings :
		$a_01_0 = {81 c5 ec 3c 06 01 89 28 } //01 00 
		$a_03_1 = {2b d3 8b da 83 44 24 10 04 83 6c 24 14 01 0f 85 90 0a 3f 00 69 d2 90 00 } //01 00 
		$a_03_2 = {83 44 24 1c 04 8b 54 24 20 03 f9 83 6c 24 30 01 8b 4c 24 10 0f 85 90 0a 3f 00 69 4c 24 90 00 } //0a 00 
		$a_01_3 = {81 c3 48 00 03 01 89 5c 24 14 89 19 } //0a 00 
		$a_03_4 = {30 35 88 27 04 01 90 02 4f 89 02 90 00 } //01 00 
		$a_03_5 = {83 44 24 10 04 81 c2 90 01 04 ff 4c 24 1c 89 0d 90 01 04 0f 85 90 0a 3f 00 69 c8 90 00 } //0a 00 
		$a_03_6 = {05 10 f9 07 01 90 02 0a 89 06 90 00 } //01 00 
		$a_01_7 = {2b 44 24 10 2d d0 6c 01 00 89 44 24 10 8b 44 24 14 8b 00 } //0b 00 
		$a_03_8 = {8d 4c 03 01 90 02 0a 8b 0a 69 f6 90 02 2f 81 c1 54 31 09 01 90 02 0f 89 0a 90 02 0a 83 c2 04 90 02 1f 75 90 00 } //01 00 
		$a_03_9 = {b8 59 00 00 00 2b 05 90 01 04 83 f0 0d 89 05 90 1b 00 81 2d 90 01 04 01 00 00 00 81 3d 90 1b 02 00 00 00 00 75 d6 e9 90 00 } //0a 00 
		$a_01_10 = {21 54 68 69 73 20 2d 37 41 66 72 61 6d 20 63 61 6e 6e 6f 74 20 62 65 20 72 75 6e 20 69 6e 20 44 4f 53 20 6d 6f 64 65 2e } //01 00  !This -7Afram cannot be run in DOS mode.
		$a_01_11 = {58 3a 5c 68 65 6d 69 74 65 72 61 74 61 5c 63 6f 6e 66 65 72 76 61 63 65 6f 75 73 5c 73 70 69 72 65 77 61 72 64 5c 77 6f 72 64 73 6d 69 74 68 2e 70 64 62 } //00 00  X:\hemiterata\confervaceous\spireward\wordsmith.pdb
		$a_00_12 = {5d 04 00 00 c8 c8 03 80 5c 25 } //00 00 
	condition:
		any of ($a_*)
 
}