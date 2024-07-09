
rule Ransom_Win64_BianLian_PC_MTB{
	meta:
		description = "Ransom:Win64/BianLian.PC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //1
		$a_03_1 = {69 74 27 73 20 63 6f 6d 70 6c 65 74 65 20 6c 6f 73 73 2e 0d 0a ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 49 6e 20 31 30 20 64 61 79 73 20 2d 20 } //2
		$a_03_2 = {6d 61 69 6e 2e 53 63 61 6e 46 6f 72 46 69 6c 65 73 2e 66 75 6e 63 31 ?? 6d 61 69 6e 2e 6d 61 69 6e } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2) >=3
 
}