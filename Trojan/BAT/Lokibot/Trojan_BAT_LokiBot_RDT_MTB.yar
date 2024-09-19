
rule Trojan_BAT_LokiBot_RDT_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.RDT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 07 11 10 11 11 6e 11 14 20 ff 00 00 00 5f 6a 61 d2 9c } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}