
rule Trojan_BAT_LokiBot_CCAW_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.CCAW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {02 03 61 04 59 20 00 01 00 00 58 0a 2b 00 06 } //1
		$a_01_1 = {07 11 0a 11 0f 20 00 01 00 00 5d d2 9c 00 11 09 17 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}