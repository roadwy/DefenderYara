
rule Trojan_BAT_LokiBot_RDE_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.RDE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {02 06 02 8e 69 6a 5d d4 02 06 02 8e 69 6a 5d d4 91 03 06 03 8e 69 6a 5d d4 91 61 } //2
		$a_01_1 = {02 06 17 6a 58 02 8e 69 6a 5d d4 91 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}