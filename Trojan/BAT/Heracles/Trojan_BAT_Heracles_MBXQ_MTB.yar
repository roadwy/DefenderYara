
rule Trojan_BAT_Heracles_MBXQ_MTB{
	meta:
		description = "Trojan:BAT/Heracles.MBXQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {06 09 91 9c 06 09 11 09 9c 06 08 91 06 09 91 58 20 00 01 00 00 5d 13 0a } //1
		$a_01_1 = {65 66 2d 33 38 32 63 66 65 66 61 39 61 64 66 } //1 ef-382cfefa9adf
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}