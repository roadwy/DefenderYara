
rule Trojan_BAT_LokiBot_Y_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.Y!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {0a 1f 10 28 90 01 01 00 00 0a 03 07 6f 90 01 01 00 00 0a 61 d1 13 04 12 04 28 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}