
rule Trojan_BAT_ZgRAT_AB_MTB{
	meta:
		description = "Trojan:BAT/ZgRAT.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {02 8e 69 1f 10 da 11 02 16 1f 10 28 } //2
		$a_01_1 = {02 16 11 0a 16 02 8e 69 1f 10 da 28 } //2
		$a_01_2 = {02 8e 69 1f 11 da 17 d6 8d } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}