
rule TrojanDownloader_BAT_QuasarRAT_G_MTB{
	meta:
		description = "TrojanDownloader:BAT/QuasarRAT.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {06 07 02 07 18 5a 18 6f 90 01 01 00 00 0a 1f 10 28 90 01 01 00 00 0a 9c 07 17 58 0b 07 06 8e 69 32 e2 06 2a 90 00 } //02 00 
		$a_03_1 = {13 06 19 8d 90 01 01 00 00 01 13 90 01 01 11 90 01 01 16 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a a2 11 90 01 01 17 7e 90 01 01 00 00 0a a2 11 90 01 01 18 06 11 06 6f 90 01 01 00 00 0a a2 11 90 01 01 13 90 01 01 06 11 04 6f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}