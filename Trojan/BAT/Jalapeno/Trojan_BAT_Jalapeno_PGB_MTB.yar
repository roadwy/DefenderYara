
rule Trojan_BAT_Jalapeno_PGB_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.PGB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {38 8a ff ff ff 2a 26 7e 11 00 00 04 14 fe 01 2a 00 00 1a 7e 11 00 00 04 2a 00 1b 30 07 } //2
		$a_01_1 = {04 61 7e 48 06 00 04 28 a5 0f 00 06 1a 8d 17 00 00 01 25 16 12 01 7e 5e 06 00 04 28 fd 0f 00 06 8c 03 00 00 01 a2 25 17 12 01 7e 5f 06 00 04 28 01 } //2
		$a_01_2 = {04 61 7e 48 06 00 04 28 a5 0f 00 06 7e 6a 06 00 04 28 2d 10 00 06 7e 6b 06 00 04 28 31 10 00 06 13 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=4
 
}