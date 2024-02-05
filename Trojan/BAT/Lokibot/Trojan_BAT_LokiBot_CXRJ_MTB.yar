
rule Trojan_BAT_LokiBot_CXRJ_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.CXRJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {16 0b 2b 21 08 06 07 6f 90 01 04 13 0e 12 0e 28 90 01 04 13 0b 11 05 09 11 0b 9c 09 17 58 0d 07 17 58 0b 07 08 6f 90 01 04 fe 04 13 0c 11 0c 2d d0 06 17 58 0a 06 08 6f 90 01 04 fe 04 13 0d 11 0d 2d b9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}