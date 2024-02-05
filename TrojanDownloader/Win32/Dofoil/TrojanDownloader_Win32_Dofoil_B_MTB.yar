
rule TrojanDownloader_Win32_Dofoil_B_MTB{
	meta:
		description = "TrojanDownloader:Win32/Dofoil.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 02 00 "
		
	strings :
		$a_03_0 = {0f b6 40 02 eb 90 01 02 40 eb 90 01 05 b9 90 01 04 eb 90 01 05 eb 90 01 02 eb 90 01 02 f7 e1 eb 90 01 06 01 d8 74 07 75 05 90 01 05 50 c3 90 00 } //02 00 
		$a_03_1 = {8b 4c 24 04 57 f7 c1 03 00 00 00 74 90 01 01 8a 01 41 84 c0 74 90 01 01 f7 c1 03 00 00 00 75 90 01 01 8b 01 ba ff fe fe 7e 03 d0 83 f0 ff 33 c2 83 c1 04 a9 00 01 01 81 90 00 } //01 00 
		$a_00_2 = {5c 64 72 69 76 65 72 73 5c 74 63 70 69 70 2e 73 79 73 } //01 00 
		$a_00_3 = {64 72 69 76 65 72 73 5c 62 65 65 70 2e 73 79 73 } //01 00 
		$a_00_4 = {64 75 6d 70 5f 64 75 6d 70 66 76 65 2e 73 79 73 } //00 00 
	condition:
		any of ($a_*)
 
}