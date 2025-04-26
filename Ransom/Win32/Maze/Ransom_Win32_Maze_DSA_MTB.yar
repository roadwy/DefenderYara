
rule Ransom_Win32_Maze_DSA_MTB{
	meta:
		description = "Ransom:Win32/Maze.DSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_81_0 = {73 68 69 74 2e 70 64 62 } //1 shit.pdb
		$a_81_1 = {62 6c 61 62 6c 61 62 6c 61 } //1 blablabla
		$a_81_2 = {54 6f 20 62 65 20 68 61 70 70 79 20 6f 6e 65 20 6d 75 73 74 20 61 74 20 6c 65 61 73 74 20 6f 6e 63 65 20 61 20 6c 69 66 65 20 72 61 } //1 To be happy one must at least once a life ra
		$a_81_3 = {63 72 65 65 70 79 73 68 69 74 2e 6c 6f 67 } //1 creepyshit.log
		$a_81_4 = {6f 70 65 6e 20 74 68 69 73 20 66 69 6c 65 20 6f 6e 20 79 6f 75 72 20 68 6f 73 74 20 74 6f 20 73 65 65 20 74 68 65 20 6e 65 78 74 20 70 61 72 74 } //1 open this file on your host to see the next part
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=3
 
}