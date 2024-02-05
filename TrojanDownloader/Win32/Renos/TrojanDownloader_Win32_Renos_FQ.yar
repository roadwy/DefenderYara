
rule TrojanDownloader_Win32_Renos_FQ{
	meta:
		description = "TrojanDownloader:Win32/Renos.FQ,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 03 00 "
		
	strings :
		$a_03_0 = {8b f8 8b f1 2b f9 8a 0e 80 f1 90 01 01 88 0c 37 74 90 01 01 90 02 03 46 90 02 03 75 90 00 } //02 00 
		$a_01_1 = {b9 0a 00 00 00 b8 68 58 4d 56 66 ba 58 56 ed 81 fb 68 58 4d 56 0f 94 c0 0f b6 c0 } //02 00 
		$a_01_2 = {33 c0 50 0f 01 4c 24 fe 58 c3 } //02 00 
		$a_03_3 = {81 fe 00 00 00 d0 90 03 01 01 a3 a2 90 01 03 00 90 02 06 77 08 81 fe 00 00 00 80 73 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}