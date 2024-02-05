
rule Trojan_BAT_LokiBot_CXIR_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.CXIR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {11 05 09 5d 13 09 11 05 09 5b 13 0a 08 11 09 11 0a 6f 90 01 04 13 0b 07 11 06 12 0b 28 90 01 04 9c 11 06 17 58 13 06 11 05 17 58 13 05 11 05 09 11 04 5a 32 c9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}