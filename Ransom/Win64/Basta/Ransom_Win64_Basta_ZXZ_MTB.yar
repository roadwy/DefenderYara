
rule Ransom_Win64_Basta_ZXZ_MTB{
	meta:
		description = "Ransom:Win64/Basta.ZXZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 d0 41 0f b6 c5 03 d2 03 c0 49 c1 ed 10 4d 33 4c d0 02 4d 33 0c c0 4c 31 4d b7 0f b6 c1 48 8d 0d ?? ?? ?? ?? 44 8d 04 00 41 0f b6 c5 4e 8b 4c c1 } //4
		$a_03_1 = {49 33 c4 48 89 41 28 49 8b 42 20 48 33 41 30 49 33 c5 48 89 41 30 49 8b 42 ?? 49 83 c2 40 48 33 41 38 48 33 c2 4c 89 55 ef 48 83 6d 77 01 48 8d 15 a3 d5 07 00 48 89 41 38 0f 85 } //5
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*5) >=9
 
}