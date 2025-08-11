
rule Trojan_BAT_FormBook_SKC_MTB{
	meta:
		description = "Trojan:BAT/FormBook.SKC!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 03 11 06 11 07 91 6f 74 00 00 0a 00 00 11 07 17 58 13 07 11 07 09 fe 04 13 08 11 08 2d e1 } //1
		$a_01_1 = {00 02 06 07 6f 71 00 00 0a 0c 04 03 6f 72 00 00 0a 59 0d 09 19 fe 04 16 fe 01 13 04 11 04 2c 2e } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_BAT_FormBook_SKC_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.SKC!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 02 06 07 6f 71 00 00 0a 0c 04 03 6f 72 00 00 0a 59 0d 09 19 fe 04 16 fe 01 13 04 11 04 2c 2e 00 03 12 02 28 73 00 00 0a 6f 74 00 00 0a 00 03 12 02 28 75 00 00 0a 6f 74 00 00 0a 00 03 12 02 28 76 00 00 0a 6f 74 00 00 0a 00 00 2b 56 09 16 fe 02 13 05 11 05 2c 4c 00 19 8d 50 00 00 01 25 16 12 02 28 73 00 00 0a 9c 25 17 12 02 28 75 00 00 0a 9c 25 18 12 02 28 76 00 00 0a 9c 13 06 16 13 07 2b 14 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}