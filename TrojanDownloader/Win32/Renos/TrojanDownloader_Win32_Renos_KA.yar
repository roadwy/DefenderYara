
rule TrojanDownloader_Win32_Renos_KA{
	meta:
		description = "TrojanDownloader:Win32/Renos.KA,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {ff d7 99 b9 19 00 00 00 f7 f9 8b 8c 24 90 01 02 00 00 8b c5 83 c2 08 2b c2 8d 34 18 89 0e ff d7 99 b9 ff 00 00 00 6a 00 90 00 } //01 00 
		$a_01_1 = {50 68 82 00 00 00 53 ff 15 } //01 00 
		$a_03_2 = {25 ff 00 00 00 8a 4c 04 90 01 01 8a 04 2a 32 c8 33 c0 88 4d 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}