
rule Ransom_Win64_DireWolf_A{
	meta:
		description = "Ransom:Win64/DireWolf.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {73 69 7a 65 20 3d 20 2c 20 74 ?? 69 6c 20 3d 20 2e 64 69 72 65 77 6f 6c 66 2f } //1
		$a_01_1 = {6d 61 69 6e 2e 65 6e 63 72 79 70 74 46 69 6c 65 2e 66 75 6e 63 32 00 6d 61 69 6e 2e } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}