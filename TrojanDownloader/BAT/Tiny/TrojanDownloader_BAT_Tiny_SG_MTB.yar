
rule TrojanDownloader_BAT_Tiny_SG_MTB{
	meta:
		description = "TrojanDownloader:BAT/Tiny.SG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {00 06 72 01 00 00 70 6f 10 00 00 0a 28 11 00 00 0a 28 12 00 00 0a 0b } //00 00 
	condition:
		any of ($a_*)
 
}