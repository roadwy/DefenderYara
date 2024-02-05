
rule Trojan_BAT_LokiBot_RDI_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.RDI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {09 11 04 11 22 58 11 21 11 23 58 6f 90 01 04 13 24 12 24 28 50 01 00 0a 13 25 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}