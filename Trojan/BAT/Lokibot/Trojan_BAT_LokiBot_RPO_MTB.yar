
rule Trojan_BAT_LokiBot_RPO_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.RPO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 1f 11 0d 09 18 d8 0d 09 20 a0 86 01 00 fe 02 13 04 11 04 2c 14 09 6c 23 00 00 00 00 00 6a e8 40 5b } //00 00 
	condition:
		any of ($a_*)
 
}