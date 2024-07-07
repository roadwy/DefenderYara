
rule Trojan_BAT_AgenTesla_MBFW_MTB{
	meta:
		description = "Trojan:BAT/AgenTesla.MBFW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 03 00 00 "
		
	strings :
		$a_01_0 = {61 9e 06 1d 06 1d 95 07 1d 95 61 } //1
		$a_01_1 = {6f 00 76 00 72 00 66 00 6c 00 77 00 2e 00 65 00 78 00 65 00 00 00 00 00 22 00 01 00 01 00 50 00 72 00 6f } //10
		$a_01_2 = {45 43 58 65 76 00 41 74 74 72 69 62 75 74 65 } //10
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10) >=21
 
}