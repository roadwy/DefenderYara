
rule TrojanDownloader_BAT_Formbook_KAI_MTB{
	meta:
		description = "TrojanDownloader:BAT/Formbook.KAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {2b 1c 72 f3 90 01 02 70 7e 90 01 03 04 2b 90 01 01 2b 90 01 01 2b 90 01 01 74 90 01 03 1b 2b 90 01 01 2b 90 01 01 2b 90 01 01 2a 28 90 01 03 06 2b 90 01 01 6f 90 01 03 0a 2b e2 90 00 } //01 00 
		$a_03_1 = {16 2d 1a 2b 90 01 01 2b 90 01 01 2b 90 01 01 91 6f 25 00 00 0a 90 00 } //01 00 
		$a_03_2 = {07 6f 26 00 00 0a 0a 06 13 90 01 01 16 2d c7 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}