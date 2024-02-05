
rule Trojan_BAT_LokiBot_CPA_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.CPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {11 07 6f 09 00 00 0a 13 08 06 6f 0a 00 00 0a 13 09 11 08 11 09 28 90 01 04 13 09 11 09 28 02 90 01 03 13 0a 11 0a 6f 90 01 04 13 0b 11 0b 90 00 } //01 00 
		$a_01_1 = {35 39 2e 35 38 2e 31 2e 36 33 } //00 00 
	condition:
		any of ($a_*)
 
}