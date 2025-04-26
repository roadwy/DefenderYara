
rule Ransom_MSIL_Maze_CCHD_MTB{
	meta:
		description = "Ransom:MSIL/Maze.CCHD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {67 65 74 5f 6d 61 7a 65 5f } //1 get_maze_
		$a_01_1 = {67 65 74 5f 44 45 43 52 59 50 54 5f 46 49 4c 45 53 } //1 get_DECRYPT_FILES
		$a_01_2 = {57 68 61 74 20 68 61 70 70 65 6e 65 64 3f } //1 What happened?
		$a_01_3 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 2c 20 64 6f 63 75 6d 65 6e 74 73 2c 20 70 68 6f 74 6f 73 2c 20 64 61 74 61 62 61 73 65 73 2c 20 61 6e 64 20 6f 74 68 65 72 20 69 6d 70 6f 72 74 61 6e 74 20 64 61 74 61 20 61 72 65 20 73 61 66 65 6c 79 20 65 6e 63 72 79 70 74 65 64 20 77 69 74 68 20 72 65 6c 69 61 62 6c 65 20 61 6c 67 6f 72 69 74 68 6d 73 } //1 All your files, documents, photos, databases, and other important data are safely encrypted with reliable algorithms
		$a_01_4 = {48 6f 77 20 74 6f 20 67 65 74 20 6d 79 20 66 69 6c 65 73 20 62 61 63 6b 3f } //1 How to get my files back?
		$a_01_5 = {54 68 65 20 6f 6e 6c 79 20 6d 65 74 68 6f 64 20 74 6f 20 72 65 73 74 6f 72 65 20 79 6f 75 72 20 66 69 6c 65 73 20 69 73 20 74 6f 20 70 75 72 63 68 61 73 65 20 61 20 75 6e 69 71 75 65 20 66 6f 72 20 79 6f 75 20 70 72 69 76 61 74 65 20 6b 65 79 20 77 68 69 63 68 20 69 73 20 73 65 63 75 72 65 6c 79 20 73 74 6f 72 65 64 20 6f 6e 20 6f 75 72 20 73 65 72 76 65 72 73 } //1 The only method to restore your files is to purchase a unique for you private key which is securely stored on our servers
		$a_01_6 = {57 65 20 75 6e 64 65 72 73 74 61 6e 64 20 79 6f 75 72 20 73 74 72 65 73 73 20 61 6e 64 20 77 6f 72 72 79 } //1 We understand your stress and worry
		$a_01_7 = {44 00 45 00 43 00 52 00 59 00 50 00 54 00 2d 00 46 00 49 00 4c 00 45 00 53 00 2e 00 74 00 78 00 74 00 } //1 DECRYPT-FILES.txt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}