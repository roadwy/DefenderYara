
rule Trojan_BAT_LokiBot_NS_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.NS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {04 11 04 02 11 04 02 6f 90 01 03 0a 5d 6f 90 01 03 0a 7e 90 01 03 04 11 04 91 28 90 01 03 06 9c 11 04 17 58 13 04 11 04 7e 90 01 03 04 8e 69 fe 04 13 05 11 05 2d c5 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}