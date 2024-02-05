
rule Trojan_BAT_LokiBot_CND_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.CND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {28 65 02 00 06 72 90 01 01 0b 00 70 72 90 01 01 0b 00 70 28 26 02 00 06 17 8d 90 01 01 00 00 01 25 16 1f 2d 9d 28 27 02 00 06 0b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}