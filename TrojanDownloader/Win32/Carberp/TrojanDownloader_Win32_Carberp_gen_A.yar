
rule TrojanDownloader_Win32_Carberp_gen_A{
	meta:
		description = "TrojanDownloader:Win32/Carberp.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {32 44 24 01 02 44 24 02 88 44 24 01 8b ca 32 4c 24 02 02 c8 88 4c 24 02 32 54 24 03 02 14 24 } //01 00 
		$a_01_1 = {8d 54 24 08 8a 18 80 f3 18 81 e3 ff 00 00 00 33 d9 88 1a 41 } //01 00 
		$a_01_2 = {80 3c 07 a1 75 27 80 7c 07 05 c7 75 20 } //01 00 
		$a_01_3 = {80 7c 07 06 80 75 19 80 7c 07 0f c3 75 12 } //01 00 
		$a_01_4 = {03 d2 33 c2 33 d2 8a d3 33 c2 88 04 3e 84 c0 75 04 c6 04 3e ff 47 8a 04 3e } //01 00 
		$a_01_5 = {89 0b 83 c2 05 c6 02 c3 c7 44 24 0c 30 00 00 00 c7 44 24 10 80 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}