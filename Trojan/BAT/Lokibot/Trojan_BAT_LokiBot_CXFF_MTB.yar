
rule Trojan_BAT_LokiBot_CXFF_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.CXFF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {13 05 11 05 17 6f 90 01 04 11 05 08 09 6f 90 01 04 13 06 73 2d 05 00 0a 13 07 11 07 11 06 17 73 90 01 04 13 08 11 08 07 16 07 8e 69 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}