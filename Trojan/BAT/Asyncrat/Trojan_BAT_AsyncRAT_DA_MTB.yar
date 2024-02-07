
rule Trojan_BAT_AsyncRAT_DA_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 0a 00 00 0a 00 "
		
	strings :
		$a_01_0 = {4c 00 4c 00 4c 00 4d 00 4c 00 4c 00 65 00 4c 00 74 00 4c 00 68 00 4c 00 6f 00 4c 00 64 00 4c 00 30 00 4c 00 4c 00 4c 00 } //0a 00  LLLMLLeLtLhLoLdL0LLL
		$a_01_1 = {4e 00 4e 00 4d 00 4e 00 4e 00 65 00 4e 00 4e 00 74 00 4e 00 4e 00 68 00 4e 00 6f 00 4e 00 4e 00 64 00 4e 00 30 00 4e 00 4e 00 } //0a 00  NNMNNeNNtNNhNoNNdN0NN
		$a_01_2 = {4f 00 4f 00 4d 00 4f 00 4f 00 65 00 4f 00 4f 00 74 00 4f 00 4f 00 68 00 4f 00 4f 00 6f 00 4f 00 64 00 4f 00 4f 00 30 00 4f 00 4f 00 } //01 00  OOMOOeOOtOOhOOoOdOO0OO
		$a_01_3 = {4c 00 43 00 43 00 5f 00 53 00 41 00 4d 00 53 00 5f 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //01 00  LCC_SAMS_Project.Resources
		$a_01_4 = {47 00 65 00 74 00 45 00 78 00 70 00 6f 00 72 00 74 00 65 00 64 00 54 00 79 00 70 00 65 00 73 00 } //01 00  GetExportedTypes
		$a_01_5 = {45 00 78 00 65 00 63 00 75 00 74 00 65 00 52 00 65 00 61 00 64 00 65 00 72 00 } //01 00  ExecuteReader
		$a_01_6 = {43 72 65 61 74 65 5f 5f 49 6e 73 74 61 6e 63 65 5f 5f } //01 00  Create__Instance__
		$a_01_7 = {52 65 70 6c 61 63 65 } //01 00  Replace
		$a_01_8 = {54 6f 53 74 72 69 6e 67 } //01 00  ToString
		$a_01_9 = {41 63 74 69 76 61 74 6f 72 } //00 00  Activator
	condition:
		any of ($a_*)
 
}