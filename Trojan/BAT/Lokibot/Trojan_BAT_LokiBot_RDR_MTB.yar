
rule Trojan_BAT_LokiBot_RDR_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.RDR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {61 07 11 04 17 58 07 8e 69 5d 91 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}