
rule TrojanDownloader_Win32_Edogom_gen_A{
	meta:
		description = "TrojanDownloader:Win32/Edogom.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {7e 24 56 8b 74 24 0c 57 8b 7c 24 14 2b f7 8d 0c 38 8a 14 0e 02 d0 80 ea 02 40 3b c5 88 11 7c ee 5f } //01 00 
		$a_01_1 = {c6 45 d4 6a c6 45 d5 75 c6 45 d6 74 c6 45 d7 6f c6 45 d8 38 c6 45 d9 2c c6 45 da 2b c6 } //01 00 
		$a_01_2 = {c6 44 24 1a 63 c6 44 24 1b 71 c6 44 24 1c 67 c6 44 24 1d 6d c6 44 24 1e 70 c6 44 24 1f 39 } //01 00 
		$a_01_3 = {c6 44 24 60 4f c6 44 24 61 70 c6 44 24 62 7a c6 44 24 63 68 c6 44 24 64 6a c6 44 24 65 69 c6 44 24 66 5d c6 44 24 67 2a } //01 00 
		$a_01_4 = {5c 64 65 73 6b 74 6f 70 73 2e 64 61 74 00 } //00 00 
		$a_00_5 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}