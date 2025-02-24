
rule Trojan_BAT_LokiBot_AUJ_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.AUJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0b 06 20 17 24 b2 32 28 01 00 00 06 0c 12 02 28 10 00 00 0a 74 01 00 00 1b 0d 72 01 00 00 70 09 6f 11 00 00 0a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}