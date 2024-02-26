
rule TrojanDownloader_BAT_zgRAT_G_MTB{
	meta:
		description = "TrojanDownloader:BAT/zgRAT.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {06 11 06 72 90 01 02 00 70 28 90 01 01 00 00 06 28 90 01 01 00 00 2b 28 90 01 01 00 00 06 26 20 90 00 } //01 00 
		$a_01_1 = {52 65 76 65 72 73 65 } //00 00  Reverse
	condition:
		any of ($a_*)
 
}