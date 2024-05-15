
rule Trojan_BAT_LokiBot_RDQ_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.RDQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {02 6f 2d 00 00 0a 6f 2e 00 00 0a 0a 7e 90 01 04 06 25 0b 6f 2f 00 00 0a 00 07 0c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}