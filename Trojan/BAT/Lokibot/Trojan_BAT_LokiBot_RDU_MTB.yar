
rule Trojan_BAT_LokiBot_RDU_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.RDU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 0c 06 91 11 18 61 13 19 11 0c 06 17 58 11 13 5d 91 13 1a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}