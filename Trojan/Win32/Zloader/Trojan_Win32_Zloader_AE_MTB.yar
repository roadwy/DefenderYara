
rule Trojan_Win32_Zloader_AE_MTB{
	meta:
		description = "Trojan:Win32/Zloader.AE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 01 ba ff fe fe 7e 03 d0 83 f0 ff 33 c2 83 c1 04 } //01 00 
		$a_03_1 = {02 c0 02 c3 02 c1 2c 90 01 01 81 c6 90 01 04 88 44 24 13 89 35 90 01 04 89 b4 2f 90 01 04 8b 35 90 01 04 0f b6 c0 83 c7 90 01 01 8d 5c 30 01 89 1d 90 01 04 81 ff 90 01 04 0f 90 00 } //01 00 
		$a_81_2 = {3a 5c 57 69 6e 64 6f 77 73 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65 } //01 00 
		$a_03_3 = {5c 53 6c 61 76 65 5c 45 6c 73 65 5c 90 02 08 5c 54 69 6d 65 5c 90 02 10 5c 77 68 65 65 6c 2e 70 64 62 90 00 } //01 00 
		$a_81_4 = {41 74 74 65 6d 70 74 20 74 6f 20 75 73 65 20 4d 53 49 4c 20 63 6f 64 65 } //00 00 
	condition:
		any of ($a_*)
 
}