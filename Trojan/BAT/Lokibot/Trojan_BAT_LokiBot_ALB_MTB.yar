
rule Trojan_BAT_LokiBot_ALB_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.ALB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 09 16 1a 09 14 13 16 12 16 11 05 11 04 28 ?? 00 00 06 26 08 02 08 1f 3c d6 6a 1a 6a 28 ?? 00 00 06 d6 13 09 02 11 09 1f 34 d6 6a 1a 6a } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}