
rule TrojanDownloader_BAT_Heracles_CXJK_MTB{
	meta:
		description = "TrojanDownloader:BAT/Heracles.CXJK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 63 00 72 00 79 00 70 00 74 00 31 00 2e 00 70 00 77 } //00 00 
	condition:
		any of ($a_*)
 
}