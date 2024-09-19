
rule Trojan_BAT_Heracles_MBXP_MTB{
	meta:
		description = "Trojan:BAT/Heracles.MBXP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 8e b7 17 da 17 d6 8d ?? 00 00 01 0a 02 02 8e b7 17 da 91 0b } //1
		$a_01_1 = {8e b7 5d 91 61 9c 09 17 d6 0d 09 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}