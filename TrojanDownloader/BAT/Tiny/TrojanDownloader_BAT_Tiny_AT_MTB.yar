
rule TrojanDownloader_BAT_Tiny_AT_MTB{
	meta:
		description = "TrojanDownloader:BAT/Tiny.AT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 03 00 00 0a 0a 06 6f 04 00 00 0a 72 01 00 00 70 6f 05 00 00 0a 06 6f 04 00 00 0a 72 11 00 00 70 6f 06 00 00 0a 06 6f 04 00 00 0a 17 6f 07 00 00 0a 06 6f 04 00 00 0a 17 6f 08 00 00 0a 06 6f 09 00 00 0a 26 06 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_BAT_Tiny_AT_MTB_2{
	meta:
		description = "TrojanDownloader:BAT/Tiny.AT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {13 05 11 05 11 04 16 9a 6f 90 01 03 0a 6f 90 01 03 0a 13 06 11 05 11 04 17 9a 6f 90 01 03 0a 6f 90 01 03 0a 13 07 11 06 11 06 6f 90 01 03 0a 17 59 6f 90 01 03 0a 13 06 11 06 28 90 01 03 0a 13 08 28 90 01 03 0a 11 08 6f 90 01 03 0a 13 06 11 06 11 07 90 00 } //01 00 
		$a_01_1 = {64 00 65 00 2d 00 43 00 48 00 2d 00 70 00 6c 00 65 00 61 00 73 00 65 00 6e 00 6f 00 72 00 75 00 6e 00 } //00 00  de-CH-pleasenorun
	condition:
		any of ($a_*)
 
}