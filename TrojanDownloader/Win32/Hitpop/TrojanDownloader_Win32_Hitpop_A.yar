
rule TrojanDownloader_Win32_Hitpop_A{
	meta:
		description = "TrojanDownloader:Win32/Hitpop.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_03_0 = {2b c3 3d 60 ea 00 00 72 90 01 01 e8 90 01 04 8b 90 02 06 50 8d 45 ec 50 b9 90 01 04 ba 90 01 04 b8 90 00 } //01 00 
		$a_00_1 = {64 65 6c 20 25 30 } //01 00 
		$a_00_2 = {68 69 74 70 6f 70 } //01 00 
		$a_00_3 = {41 56 50 2e 42 75 74 74 6f 6e } //01 00 
		$a_00_4 = {41 56 50 2e 41 6c 65 72 74 44 69 61 6c 6f 67 } //01 00 
		$a_00_5 = {41 56 50 2e 50 72 6f 64 75 63 74 5f 4e 6f 74 69 66 69 63 61 74 69 6f 6e } //01 00 
		$a_00_6 = {41 56 50 2e 54 72 61 66 66 69 63 4d 6f 6e 43 6f 6e 6e 65 63 74 69 6f 6e 54 65 72 6d } //00 00 
	condition:
		any of ($a_*)
 
}