
rule Trojan_BAT_SpyKeyLogger_RDA_MTB{
	meta:
		description = "Trojan:BAT/SpyKeyLogger.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {6f 43 00 00 0a 80 1a 00 00 04 7e 1a 00 00 04 07 16 07 8e 69 } //00 00 
	condition:
		any of ($a_*)
 
}