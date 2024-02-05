
rule TrojanDownloader_Win32_Renos_FO{
	meta:
		description = "TrojanDownloader:Win32/Renos.FO,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {74 18 8b f8 8b f1 2b f9 8a 0e 80 f1 90 01 01 88 0c 37 74 08 8a 4e 01 46 84 c9 75 ee 90 00 } //01 00 
		$a_03_1 = {35 23 01 ef cd 50 ff 15 90 01 04 0f be 0d 90 00 } //01 00 
		$a_01_2 = {ff d7 8b e8 ff d7 2b c5 3d 35 05 00 00 0f 83 } //00 00 
	condition:
		any of ($a_*)
 
}