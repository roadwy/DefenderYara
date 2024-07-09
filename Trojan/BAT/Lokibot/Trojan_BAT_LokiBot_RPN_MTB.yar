
rule Trojan_BAT_LokiBot_RPN_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.RPN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {7e 06 00 00 04 06 28 ?? 00 00 06 d2 9c 09 17 58 0d 09 17 32 cf 06 17 58 0a 08 17 58 0c 08 20 00 4e 01 00 32 bb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}