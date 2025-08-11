
rule Trojan_BAT_DCRat_LM_MTB{
	meta:
		description = "Trojan:BAT/DCRat.LM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {02 28 3f 00 00 0a 6f 40 00 00 0a 0a 14 0b 06 6f 41 00 00 0a 8e 69 16 31 10 17 8d 0b 00 00 01 25 16 16 8d 15 00 00 01 a2 0b 06 14 07 74 0a 00 00 1b 6f 42 00 00 0a 26 } //20
		$a_01_1 = {73 38 00 00 0a 0b 00 07 02 6f 39 00 00 0a 0c 08 28 3a 00 00 0a 73 3b 00 00 0a 0a de 20 08 2c 06 08 6f 3c 00 00 0a dc 28 1e 00 00 0a 20 d0 07 00 00 28 3d 00 00 0a 28 3e 00 00 0a de c9 06 2a } //10
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}