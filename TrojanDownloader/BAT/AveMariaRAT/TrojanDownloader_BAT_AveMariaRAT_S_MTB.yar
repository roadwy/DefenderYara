
rule TrojanDownloader_BAT_AveMariaRAT_S_MTB{
	meta:
		description = "TrojanDownloader:BAT/AveMariaRAT.S!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {13 05 08 11 05 6f 90 01 01 00 00 0a 11 04 17 58 13 04 11 04 09 6f 90 01 01 00 00 0a 32 e0 14 08 28 90 01 01 00 00 2b 0d de 43 73 90 00 } //02 00 
		$a_03_1 = {2b 0a 2b 0b 18 2b 0b 1f 10 2b 0e 2a 02 2b f3 03 2b f2 6f 90 01 01 00 00 0a 2b ee 28 90 00 } //01 00 
		$a_01_2 = {47 65 74 54 79 70 65 } //01 00 
		$a_01_3 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}