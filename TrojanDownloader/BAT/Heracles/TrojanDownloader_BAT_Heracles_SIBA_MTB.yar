
rule TrojanDownloader_BAT_Heracles_SIBA_MTB{
	meta:
		description = "TrojanDownloader:BAT/Heracles.SIBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {fe 0e 01 00 72 90 01 04 fe 0e 02 00 73 90 01 04 fe 0e 03 00 fe 0c 01 00 28 90 01 04 6f 90 01 04 fe 0e 04 00 38 90 01 04 fe 0d 04 00 28 90 01 04 fe 0e 05 00 fe 0c 05 00 28 90 01 04 fe 0c 02 00 28 90 01 04 da fe 0e 06 00 fe 0c 03 00 fe 0c 06 00 28 90 01 04 6f 90 01 04 26 90 02 10 fe 0d 04 00 28 90 01 04 fe 0e 07 00 fe 0c 07 00 3a 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}