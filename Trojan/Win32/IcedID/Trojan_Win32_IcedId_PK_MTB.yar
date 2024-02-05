
rule Trojan_Win32_IcedId_PK_MTB{
	meta:
		description = "Trojan:Win32/IcedId.PK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 ff 8b f0 33 c9 8b 84 90 01 05 ba 90 01 04 f7 e2 03 c7 89 84 90 01 05 83 d2 00 41 8b fa 3b ce 75 90 00 } //01 00 
		$a_01_1 = {74 68 75 73 20 62 61 6c 20 48 69 74 20 72 69 76 65 20 43 6f 6f 6b 20 4c 69 6e } //01 00 
		$a_01_2 = {5c 54 68 69 73 5c 34 39 5c 73 6f 6c 64 69 65 72 5c 48 6f 70 65 2e 70 64 62 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_IcedId_PK_MTB_2{
	meta:
		description = "Trojan:Win32/IcedId.PK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b7 c2 2b d8 83 c3 1e 8b 44 24 18 81 c7 90 01 04 89 3d 90 01 04 89 1d 90 01 04 89 38 a1 90 01 04 8b 7c 24 18 2b c6 03 d0 83 c7 04 ff 4c 24 1c 89 54 24 90 01 01 89 7c 24 90 01 01 0f 90 00 } //01 00 
		$a_01_1 = {5c 53 74 65 70 5c 53 68 6f 65 5c 57 61 76 65 5c 70 75 6c 6c 5c 41 6c 6c 6f 77 5c 63 6f 6e 64 69 74 69 6f 6e 5c 63 6f 70 79 2e 70 64 62 } //00 00 
	condition:
		any of ($a_*)
 
}