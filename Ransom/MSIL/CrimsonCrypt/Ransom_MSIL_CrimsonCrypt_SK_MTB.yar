
rule Ransom_MSIL_CrimsonCrypt_SK_MTB{
	meta:
		description = "Ransom:MSIL/CrimsonCrypt.SK!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {7e 2a 01 00 04 73 d3 00 00 0a 25 7e 25 01 00 04 7e a3 00 00 04 20 5f b0 66 06 2b 2f 7e f6 00 00 04 2b 2f 2b 34 6f 43 00 00 0a 25 17 6f 4c 00 00 0a 25 17 6f 09 00 00 0a 25 7e a3 00 00 04 20 3a b0 66 06 2b 1b 2b 20 2b 25 26 2a 28 1b 00 00 06 2b ca 28 ff 00 00 06 2b ca 28 35 01 00 06 2b c5 28 1b 00 00 06 2b de 6f 44 00 00 0a 2b d9 28 41 01 00 06 2b d4 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}