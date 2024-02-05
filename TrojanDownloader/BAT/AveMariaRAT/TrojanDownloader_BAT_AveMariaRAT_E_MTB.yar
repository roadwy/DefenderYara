
rule TrojanDownloader_BAT_AveMariaRAT_E_MTB{
	meta:
		description = "TrojanDownloader:BAT/AveMariaRAT.E!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {02 16 02 8e 69 90 01 01 2d 90 01 01 26 26 26 2b 90 01 01 28 90 01 01 00 00 0a 2b 00 2a 90 00 } //01 00 
		$a_03_1 = {08 8e 69 6f 90 01 01 00 00 0a 0d 12 90 01 01 08 09 28 90 01 01 00 00 06 09 16 fe 90 01 01 13 90 01 01 11 90 01 01 2d 90 01 01 11 90 01 01 6f 90 01 01 00 00 0a 90 0a 3a 00 06 6f 90 01 01 00 00 0a 0b 20 90 01 03 00 8d 90 01 01 00 00 01 0c 16 0d 07 08 16 90 00 } //01 00 
		$a_03_2 = {00 00 0a 74 1b 00 00 01 90 01 02 04 26 06 2b 90 01 01 0a 2b fa 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}