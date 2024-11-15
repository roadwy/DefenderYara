
rule Ransom_Win64_Maze_GV_MTB{
	meta:
		description = "Ransom:Win64/Maze.GV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 07 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 52 75 6e } //1 main.Run
		$a_01_1 = {6d 61 69 6e 2e 64 61 74 61 4d 61 7a 65 64 65 73 6b 74 6f 70 50 6e 67 } //5 main.dataMazedesktopPng
		$a_01_2 = {44 45 43 52 59 50 54 2d 46 49 4c 45 53 2e 74 78 74 } //5 DECRYPT-FILES.txt
		$a_01_3 = {6d 61 69 6e 2e 64 6f 45 6e 63 72 79 70 74 } //1 main.doEncrypt
		$a_01_4 = {6d 61 69 6e 2e 64 6f 44 65 63 72 79 70 74 } //1 main.doDecrypt
		$a_01_5 = {74 79 70 65 3a 2e 65 71 2e 6d 61 69 6e 2e 43 6f 6e 66 69 67 } //1 type:.eq.main.Config
		$a_01_6 = {6f 73 2e 28 2a 50 72 6f 63 65 73 73 29 2e 6b 69 6c 6c } //1 os.(*Process).kill
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=9
 
}