
rule Ransom_MSIL_Mallox_SG_MTB{
	meta:
		description = "Ransom:MSIL/Mallox.SG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {72 fe 09 00 70 17 8d 9d 00 00 01 25 16 1f 2c 9d 28 d4 00 00 0a 0d } //2
		$a_01_1 = {72 03 0c 00 70 28 e0 00 00 0a 11 04 28 e1 00 00 0a 13 10 11 10 28 e2 00 00 0a 26 11 10 06 7b 28 03 00 04 72 13 0c 00 70 28 ad 00 00 0a 13 11 11 11 28 e3 00 00 0a 2d 2d 11 11 28 e4 00 00 0a 25 11 0e 16 11 0e 8e 69 6f 1f 00 00 0a 6f 17 00 00 0a 11 11 14 1a 28 69 01 00 06 26 11 10 14 1a 28 69 01 00 06 26 11 11 28 e5 00 00 0a 13 0f de 03 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}