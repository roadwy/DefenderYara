
rule Ransom_MSIL_FileCoder_SGD_MTB{
	meta:
		description = "Ransom:MSIL/FileCoder.SGD!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {24 31 30 66 31 66 30 33 37 2d 66 65 64 39 2d 34 64 61 32 2d 38 63 36 62 2d 37 35 62 64 64 33 32 34 62 38 66 39 } //1 $10f1f037-fed9-4da2-8c6b-75bdd324b8f9
		$a_01_1 = {5c 63 72 79 70 74 6f 62 72 69 63 6b 2e 70 64 62 } //1 \cryptobrick.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}