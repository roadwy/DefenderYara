
rule TrojanDownloader_Win32_Zlob_gen_BQ{
	meta:
		description = "TrojanDownloader:Win32/Zlob.gen!BQ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a ff b2 67 b8 90 01 02 00 10 89 90 01 03 00 10 e8 90 01 02 00 00 90 00 } //01 00 
		$a_01_1 = {8a da 32 d9 88 1e 46 8a 0c 37 84 c9 75 f2 5b 5f c6 06 00 } //01 00 
		$a_01_2 = {68 75 70 70 61 2e 64 6c 6c 00 44 6c 6c } //01 00 
		$a_00_3 = {72 00 65 00 73 00 3a 00 2f 00 2f 00 25 00 73 00 } //00 00  res://%s
	condition:
		any of ($a_*)
 
}