
rule Trojan_BAT_Crysan_ACY_MTB{
	meta:
		description = "Trojan:BAT/Crysan.ACY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 00 2b 0a 00 1f 64 28 90 01 01 00 00 0a 00 00 09 6f 90 01 01 00 00 0a 13 07 11 07 2d ea 11 05 73 90 01 01 00 00 0a 13 06 11 06 17 6f 90 00 } //1
		$a_03_1 = {0a 00 11 06 28 90 01 01 00 00 0a 26 00 de 1d 13 08 00 72 90 01 01 00 00 70 11 08 6f 90 01 01 00 00 0a 28 90 01 01 00 00 0a 28 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}