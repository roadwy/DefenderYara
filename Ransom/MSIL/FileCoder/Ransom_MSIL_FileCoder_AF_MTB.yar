
rule Ransom_MSIL_FileCoder_AF_MTB{
	meta:
		description = "Ransom:MSIL/FileCoder.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {13 0e 16 13 0f 2b 17 11 0e 11 0f 9a 13 10 00 11 10 28 07 00 00 06 00 00 11 0f 17 58 13 0f 11 0f 11 0e 8e 69 32 e1 } //2
		$a_01_1 = {4d 61 7a 65 5c 6f 62 6a 5c 44 65 62 75 67 5c 4d 61 7a 65 2e 70 64 62 } //1 Maze\obj\Debug\Maze.pdb
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Ransom_MSIL_FileCoder_AF_MTB_2{
	meta:
		description = "Ransom:MSIL/FileCoder.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {52 00 61 00 6e 00 73 00 6f 00 6d 00 77 00 61 00 72 00 65 00 56 00 69 00 70 00 65 00 72 00 } //1 RansomwareViper
		$a_01_1 = {56 00 69 00 70 00 65 00 72 00 5f 00 52 00 45 00 41 00 44 00 4d 00 45 00 } //1 Viper_README
		$a_01_2 = {59 00 6f 00 75 00 72 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 77 00 65 00 72 00 65 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 20 00 62 00 79 00 20 00 56 00 69 00 70 00 65 00 72 00 20 00 52 00 61 00 6e 00 73 00 6f 00 6d 00 77 00 61 00 72 00 65 00 } //1 Your files were encrypted by Viper Ransomware
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}