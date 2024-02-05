
rule TrojanDownloader_Win32_Dofoil_M{
	meta:
		description = "TrojanDownloader:Win32/Dofoil.M,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {58 87 04 24 8b 04 03 0f c8 ff e0 } //01 00 
		$a_01_1 = {83 c6 02 0f b7 16 31 d0 66 ab 49 75 f3 } //01 00 
		$a_01_2 = {ff e0 03 76 3c 8d 7e 78 8d 55 } //01 00 
		$a_01_3 = {29 c2 89 d0 c1 c0 08 88 c2 b0 e9 89 06 } //01 00 
		$a_01_4 = {56 31 d2 ac 00 c2 c1 c2 11 ac 08 c0 75 f6 } //01 00 
		$a_01_5 = {4f 75 72 5f 41 67 65 6e 74 00 5c 63 74 66 6d 6f 6e } //00 00 
	condition:
		any of ($a_*)
 
}