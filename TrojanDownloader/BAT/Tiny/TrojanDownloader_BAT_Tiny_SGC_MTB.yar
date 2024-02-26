
rule TrojanDownloader_BAT_Tiny_SGC_MTB{
	meta:
		description = "TrojanDownloader:BAT/Tiny.SGC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {1f 1c 28 11 00 00 0a 72 e5 09 00 70 28 12 00 00 0a 28 04 00 00 06 00 09 28 15 00 00 0a 26 2a } //00 00 
	condition:
		any of ($a_*)
 
}