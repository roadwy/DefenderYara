
rule Ransom_Linux_Conti_C_MTB{
	meta:
		description = "Ransom:Linux/Conti.C!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {84 c0 0f 84 14 01 00 00 48 8d 05 4f 24 00 00 48 89 c7 b8 00 00 00 00 e8 0a ed ff ff b8 00 00 00 00 e9 e3 e9 ff ff } //1
		$a_00_1 = {53 74 61 72 74 69 6e 67 20 65 6e 63 72 79 70 74 69 6f 6e 20 2d 20 43 4f 4e 54 49 20 50 4f 43 } //1 Starting encryption - CONTI POC
		$a_00_2 = {41 6c 6c 20 6f 66 20 79 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 63 75 72 72 65 6e 74 6c 79 20 65 6e 63 72 79 70 74 65 64 20 62 79 20 43 4f 4e 54 49 20 73 74 72 61 69 6e } //1 All of your files are currently encrypted by CONTI strain
		$a_00_3 = {54 68 65 20 72 61 6e 73 6f 6d 77 61 72 65 20 77 6f 6e 27 74 20 65 6e 63 72 79 70 74 20 61 6e 79 74 68 69 6e 67 20 77 69 74 68 6f 75 74 20 69 74 } //1 The ransomware won't encrypt anything without it
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}