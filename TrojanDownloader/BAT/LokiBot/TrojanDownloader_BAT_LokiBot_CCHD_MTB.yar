
rule TrojanDownloader_BAT_LokiBot_CCHD_MTB{
	meta:
		description = "TrojanDownloader:BAT/LokiBot.CCHD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0b 16 0c 38 90 01 01 00 00 00 06 28 90 01 01 00 00 0a 12 02 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 28 90 01 01 00 00 0a 07 28 90 01 01 00 00 0a 39 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}