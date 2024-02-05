
rule Trojan_BAT_LokiBot_RPK_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.RPK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {7e 45 00 00 04 0a 06 28 ad 00 00 0a 7e 45 00 00 04 02 12 02 6f ae 00 00 0a 2c 04 08 0b de 11 02 17 28 a2 00 00 06 0b de 07 06 28 af 00 00 0a dc 07 2a } //00 00 
	condition:
		any of ($a_*)
 
}