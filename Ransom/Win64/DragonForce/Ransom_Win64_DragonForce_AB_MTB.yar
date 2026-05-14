
rule Ransom_Win64_DragonForce_AB_MTB{
	meta:
		description = "Ransom:Win64/DragonForce.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_01_0 = {48 ff c6 48 89 b4 24 a0 07 00 00 48 81 fe 00 01 00 00 74 1c 48 3b b4 24 90 07 00 00 75 e2 } //6
		$a_81_1 = {2e 64 65 76 6d 61 6e } //2 .devman
		$a_81_2 = {45 6e 63 72 79 70 74 69 6f 6e 20 63 6f 6d 70 6c 65 74 65 2e 20 46 69 6c 65 73 20 65 6e 63 72 79 70 74 65 64 3a } //2 Encryption complete. Files encrypted:
	condition:
		((#a_01_0  & 1)*6+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2) >=10
 
}