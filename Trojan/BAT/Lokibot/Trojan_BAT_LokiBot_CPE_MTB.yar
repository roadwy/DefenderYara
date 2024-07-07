
rule Trojan_BAT_LokiBot_CPE_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.CPE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_03_0 = {28 25 00 00 06 72 30 02 00 70 72 34 02 00 70 6f 59 00 00 0a 0b 00 07 17 8d 90 01 04 25 16 1f 2d 9d 6f 90 01 04 0c 73 90 01 04 0d 90 00 } //5
		$a_03_1 = {09 11 06 08 11 06 9a 1f 10 28 90 01 04 d2 6f 90 01 04 00 11 06 17 58 13 06 11 06 08 8e 69 fe 04 13 07 11 07 90 00 } //5
		$a_81_2 = {43 56 33 33 31 31 32 } //1 CV33112
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5+(#a_81_2  & 1)*1) >=11
 
}