
rule TrojanDownloader_BAT_Formbook_KAJ_MTB{
	meta:
		description = "TrojanDownloader:BAT/Formbook.KAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {06 02 6f 0a 90 01 02 0a 90 01 01 2d 90 01 01 26 2b 90 01 01 0b 2b 90 01 01 73 90 01 03 0a 0c 07 08 6f 90 01 03 0a 08 6f 90 01 03 0a 0d de 90 00 } //01 00 
		$a_03_1 = {6f 14 00 00 0a 1a 2d 90 01 01 26 06 2b 90 01 01 0a 2b 90 01 01 2a 90 0a 1a 00 28 13 00 00 0a 28 01 00 00 06 90 00 } //01 00 
		$a_03_2 = {02 06 6f 15 00 00 0a 02 fe 90 01 04 06 73 90 01 03 0a 28 90 01 03 2b 28 90 01 03 2b 16 6f 90 01 03 0a 90 01 01 2d 07 26 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}