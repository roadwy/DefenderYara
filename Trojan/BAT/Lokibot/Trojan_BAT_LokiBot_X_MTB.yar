
rule Trojan_BAT_LokiBot_X_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.X!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 05 00 00 "
		
	strings :
		$a_03_0 = {02 11 06 11 07 6f ?? 00 00 0a 13 08 } //4
		$a_01_1 = {11 07 17 58 13 07 } //2 ܑ堗ܓ
		$a_01_2 = {11 06 07 fe 04 } //2
		$a_01_3 = {0a 16 09 06 1a 28 } //2 ᘊ؉⠚
		$a_01_4 = {06 1a 58 0a } //2
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=12
 
}