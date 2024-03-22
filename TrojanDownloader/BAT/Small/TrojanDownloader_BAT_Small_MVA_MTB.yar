
rule TrojanDownloader_BAT_Small_MVA_MTB{
	meta:
		description = "TrojanDownloader:BAT/Small.MVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 18 00 00 0a 11 0b 7b 11 00 00 04 28 19 00 00 0a 28 02 00 00 06 2b 34 } //00 00 
	condition:
		any of ($a_*)
 
}