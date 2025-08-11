
rule Trojan_BAT_LokiBot_ALB_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.ALB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 09 16 1a 09 14 13 16 12 16 11 05 11 04 28 ?? 00 00 06 26 08 02 08 1f 3c d6 6a 1a 6a 28 ?? 00 00 06 d6 13 09 02 11 09 1f 34 d6 6a 1a 6a } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_BAT_LokiBot_ALB_MTB_2{
	meta:
		description = "Trojan:BAT/LokiBot.ALB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {16 13 07 2b 15 00 07 11 07 07 11 07 94 03 5a 1f 64 5d 9e 00 11 07 17 58 13 07 11 07 07 8e 69 fe 04 13 08 11 08 2d de } //2
		$a_01_1 = {53 74 75 64 65 6e 74 5f 48 6f 75 73 69 6e 67 } //1 Student_Housing
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}