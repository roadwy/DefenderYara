
rule TrojanDropper_Win64_Blusimul_ARA_MTB{
	meta:
		description = "TrojanDropper:Win64/Blusimul.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_80_0 = {42 6c 75 65 73 63 72 65 65 6e 53 69 6d 75 6c 61 74 6f 72 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 42 6c 75 65 73 63 72 65 65 6e 53 69 6d 75 6c 61 74 6f 72 2e 70 64 62 } //BluescreenSimulator\obj\Release\BluescreenSimulator.pdb  2
		$a_80_1 = {73 68 75 74 64 6f 77 6e 20 74 6f 20 70 72 65 76 65 6e 74 20 64 61 6d 61 67 65 20 74 6f 20 79 6f 75 72 20 63 6f 6d 70 75 74 65 72 2e } //shutdown to prevent damage to your computer.  2
		$a_80_2 = {41 20 70 72 6f 67 72 61 6d 20 74 6f 20 73 69 6d 75 6c 61 74 65 20 42 53 4f 44 73 20 77 69 74 68 20 6c 6f 74 73 20 6f 66 20 66 65 61 74 75 72 65 73 2e } //A program to simulate BSODs with lots of features.  2
		$a_80_3 = {49 73 44 75 6d 70 43 6f 6d 70 6c 65 74 65 } //IsDumpComplete  2
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2) >=8
 
}