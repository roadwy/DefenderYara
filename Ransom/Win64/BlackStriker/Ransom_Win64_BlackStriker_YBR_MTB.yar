
rule Ransom_Win64_BlackStriker_YBR_MTB{
	meta:
		description = "Ransom:Win64/BlackStriker.YBR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_01_0 = {4c 45 49 41 2d 4d 45 2e 74 78 74 } //1 LEIA-ME.txt
		$a_01_1 = {6f 2c 20 70 61 72 65 63 65 20 71 75 65 20 73 65 75 73 20 61 72 71 75 69 76 6f 73 20 49 4e 46 45 4c 49 5a 4d 45 4e 54 45 20 66 6f 72 61 6d 20 63 72 69 70 74 6f 67 72 61 66 61 64 6f 73 2c 20 62 6c 61 20 62 6c 61 } //3 o, parece que seus arquivos INFELIZMENTE foram criptografados, bla bla
		$a_01_2 = {62 6c 61 77 73 63 72 69 70 74 46 61 69 6c 65 64 20 74 6f 20 65 78 65 63 75 74 65 20 73 65 6c 66 2d 64 65 6c 65 74 69 6e 67 20 73 63 72 69 70 74 } //1 blawscriptFailed to execute self-deleting script
		$a_01_3 = {42 6c 61 63 6b 53 74 72 69 6b 65 72 2e 70 64 62 } //1 BlackStriker.pdb
		$a_01_4 = {6c 69 62 72 61 72 79 5c 63 6f 72 65 5c 73 72 63 5c 65 73 63 61 70 65 2e 72 73 } //1 library\core\src\escape.rs
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*3+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=7
 
}