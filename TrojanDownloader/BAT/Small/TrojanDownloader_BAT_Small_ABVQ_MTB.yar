
rule TrojanDownloader_BAT_Small_ABVQ_MTB{
	meta:
		description = "TrojanDownloader:BAT/Small.ABVQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_03_0 = {0c 08 16 02 7b 90 01 01 00 00 04 28 90 01 01 00 00 0a a2 00 08 14 14 14 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 0a 06 28 90 01 01 00 00 0a 72 90 01 02 00 70 18 16 8d 90 01 01 00 00 01 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 0b 07 74 90 01 01 00 00 01 72 90 01 02 00 70 14 6f 90 01 01 00 00 0a 26 00 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}