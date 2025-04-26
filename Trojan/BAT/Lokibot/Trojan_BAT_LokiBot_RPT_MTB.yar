
rule Trojan_BAT_LokiBot_RPT_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.RPT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {02 7b 2e 01 00 04 04 02 7b 2e 01 00 04 6f 34 00 00 0a 5d 6f a9 01 00 0a 03 61 d2 2a } //1
		$a_01_1 = {55 00 73 00 73 00 72 00 20 00 69 00 73 00 20 00 62 00 61 00 63 00 6b 00 } //1 Ussr is back
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}