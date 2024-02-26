
rule TrojanDownloader_BAT_Tiny_MVG_MTB{
	meta:
		description = "TrojanDownloader:BAT/Tiny.MVG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 03 00 00 0a 72 01 00 00 70 28 04 00 00 0a 28 05 00 00 0a 72 31 00 00 70 6f 06 00 00 0a 72 53 00 00 70 6f 07 00 00 0a } //00 00 
	condition:
		any of ($a_*)
 
}