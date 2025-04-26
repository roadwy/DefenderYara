
rule Trojan_BAT_LokiBot_ALO_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.ALO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8e 69 17 59 0c 2b 19 0b 2b f5 06 07 91 0d 06 07 06 08 91 9c 06 08 09 9c 07 17 58 0b 08 17 59 0c 07 08 32 e6 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}