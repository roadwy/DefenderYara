
rule Ransom_Win32_Maze_PA_MTB{
	meta:
		description = "Ransom:Win32/Maze.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 4d f8 83 c1 01 89 4d f8 8b 55 f8 3b 55 ?? 73 ?? 8b 45 10 03 45 f8 0f b6 08 8b 55 f8 0f b6 44 15 ?? 33 c8 8b 55 ?? 03 55 f8 88 0a eb } //10
		$a_00_1 = {8b 55 f4 33 55 f0 03 55 ec 8b 45 fc 8b 4d 08 03 14 81 8b 45 fc 8b 4d 08 89 14 81 } //1
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*1) >=11
 
}
rule Ransom_Win32_Maze_PA_MTB_2{
	meta:
		description = "Ransom:Win32/Maze.PA!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {22 00 25 00 73 00 22 00 20 00 73 00 68 00 61 00 64 00 6f 00 77 00 63 00 6f 00 70 00 79 00 20 00 64 00 65 00 6c 00 65 00 74 00 65 00 } //1 "%s" shadowcopy delete
		$a_01_1 = {4d 00 61 00 7a 00 65 00 20 00 52 00 61 00 6e 00 73 00 6f 00 6d 00 77 00 61 00 72 00 65 00 } //1 Maze Ransomware
		$a_01_2 = {59 00 6f 00 75 00 72 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 68 00 61 00 76 00 65 00 20 00 62 00 65 00 65 00 6e 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 20 00 62 00 79 00 } //1 Your files have been encrypted by
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}