
rule Ransom_Win64_Cryrar_SE_MTB{
	meta:
		description = "Ransom:Win64/Cryrar.SE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 74 08 ?? c1 e6 ?? 4c 09 de 41 c1 e2 ?? 49 09 f2 41 c1 e0 ?? 4d 09 d0 4d 09 c8 4c 33 44 11 ?? 4c 89 84 0c ?? ?? ?? ?? 48 83 c1 ?? 48 83 f9 ?? 72 } //1
		$a_01_1 = {6c 75 6d 65 20 69 6e 66 6f 72 6d 61 74 69 6f 6e 73 79 73 74 65 6d 20 76 6f 6c 75 6d 65 20 69 6e 67 72 61 6d 20 66 69 6c 65 73 } //1 lume informationsystem volume ingram files
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}