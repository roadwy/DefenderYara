
rule Ransom_Win64_BazarCrypt_SX_MTB{
	meta:
		description = "Ransom:Win64/BazarCrypt.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {59 49 89 c8 48 81 c1 ?? ?? 00 00 ba ?? ?? ?? ?? 49 81 c0 ?? ?? ?? ?? 41 b9 05 00 00 00 56 48 89 e6 48 83 e4 f0 48 83 ec 30 c7 44 24 ?? 01 00 00 00 e8 ?? 00 00 00 48 89 f4 5e c3 } //2
		$a_03_1 = {b9 4c 77 26 07 44 8b fa 33 db e8 ?? ?? 00 00 b9 49 f7 02 78 4c 8b e8 e8 ?? ?? 00 00 b9 58 a4 53 e5 48 89 44 24 ?? e8 ?? ?? 00 00 b9 10 e1 8a c3 48 8b f0 e8 ?? ?? 00 00 b9 af b1 5c 94 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}