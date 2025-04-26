
rule Trojan_BAT_Heracles_BAC_MTB{
	meta:
		description = "Trojan:BAT/Heracles.BAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 8e 69 8d 05 00 00 01 0a 16 0b 2b 13 06 07 02 07 91 03 07 03 8e 69 5d 91 61 d2 9c 07 17 58 0b 07 02 8e 69 32 e7 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}
rule Trojan_BAT_Heracles_BAC_MTB_2{
	meta:
		description = "Trojan:BAT/Heracles.BAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 11 09 11 0b 58 06 11 0b 58 47 08 11 0b 08 6f 05 00 00 0a 5d 6f 06 00 00 0a 61 d2 52 00 11 0b 17 58 13 0b 11 0b 07 8e 69 fe 04 13 0c 11 0c 2d cf } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}