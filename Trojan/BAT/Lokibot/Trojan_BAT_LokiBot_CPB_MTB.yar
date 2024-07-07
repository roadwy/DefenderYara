
rule Trojan_BAT_LokiBot_CPB_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.CPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {28 37 00 00 0a 25 26 7e 0d 00 00 04 02 11 00 6f 2f 00 00 0a 25 } //5
		$a_03_1 = {03 28 49 00 00 06 25 26 13 00 38 90 01 04 dd 90 01 04 26 38 90 01 04 1f 61 6a 03 28 4b 00 00 06 13 00 38 90 00 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}