
rule Trojan_BAT_LokiBot_CXRL_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.CXRL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {11 05 09 5b 13 0b 08 11 0a 11 0b 6f 90 01 04 13 0c 07 11 06 12 0c 28 90 01 04 9c 11 06 17 58 13 06 11 05 17 58 13 05 00 11 05 09 11 04 5a fe 04 13 0d 11 0d 2d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}