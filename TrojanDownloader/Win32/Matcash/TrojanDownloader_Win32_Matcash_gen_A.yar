
rule TrojanDownloader_Win32_Matcash_gen_A{
	meta:
		description = "TrojanDownloader:Win32/Matcash.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 02 00 "
		
	strings :
		$a_00_0 = {2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 } //02 00 
		$a_01_1 = {56 85 c0 74 12 8d 70 02 66 8b 10 83 c0 02 66 85 d2 75 f5 2b c6 d1 f8 3b d8 7e 02 8b d8 b8 ff ff ff 7f 2b c3 3b c5 7d 0a 68 57 00 07 80 e8 } //01 00 
		$a_00_2 = {56 00 69 00 64 00 65 00 6f 00 42 00 69 00 6f 00 73 00 44 00 61 00 74 00 65 00 } //01 00 
		$a_00_3 = {53 00 79 00 73 00 74 00 65 00 6d 00 42 00 69 00 6f 00 73 00 44 00 61 00 74 00 65 00 } //01 00 
		$a_00_4 = {41 00 64 00 76 00 65 00 72 00 74 00 69 00 73 00 6d 00 65 00 6e 00 74 00 } //00 00 
	condition:
		any of ($a_*)
 
}