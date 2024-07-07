
rule Ransom_Linux_Lilock_C_MTB{
	meta:
		description = "Ransom:Linux/Lilock.C!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {08 9b 82 30 e0 e7 7a 83 44 39 34 dc 14 b4 74 04 10 d2 f2 49 ac 4a 18 6a a3 28 de 1a 83 c9 a3 d5 1c 11 a0 6c d8 e3 11 0d 2e 94 71 84 c2 4d c4 4e da 2e 81 74 1b 25 87 60 c0 54 88 4b 86 5d f9 58 08 3a b5 eb ec cf 2e 51 ea bb 00 3a 9b 78 01 1b 8b 93 2f 5a b0 0f 0b 85 d2 29 57 e1 55 19 20 56 3c a1 da 06 41 ab 38 } //1
	condition:
		((#a_00_0  & 1)*1) >=1
 
}