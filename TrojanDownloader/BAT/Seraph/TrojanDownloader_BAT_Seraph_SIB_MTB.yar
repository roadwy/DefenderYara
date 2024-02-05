
rule TrojanDownloader_BAT_Seraph_SIB_MTB{
	meta:
		description = "TrojanDownloader:BAT/Seraph.SIB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {0a 16 0b 2b 90 01 01 06 02 07 28 90 01 04 03 07 03 28 90 01 04 5d 28 90 01 04 61 d1 28 90 01 04 26 07 17 58 0b 07 02 28 90 01 04 32 90 01 01 06 28 90 01 04 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}