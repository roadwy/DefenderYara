
rule Ransom_Win64_Basta_AG_MTB{
	meta:
		description = "Ransom:Win64/Basta.AG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {45 3a 5c 63 70 70 5c 67 69 74 35 5c 78 36 34 5c 64 6c 6c 5c 53 75 64 53 6f 6c 76 65 72 2e 70 64 62 } //1 E:\cpp\git5\x64\dll\SudSolver.pdb
		$a_01_1 = {56 69 73 69 62 6c 65 45 6e 74 72 79 } //1 VisibleEntry
		$a_01_2 = {57 00 65 00 62 00 63 00 61 00 6d 00 20 00 53 00 75 00 64 00 6f 00 6b 00 75 00 20 00 53 00 6f 00 6c 00 76 00 65 00 72 00 20 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 } //1 Webcam Sudoku Solver Version
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}