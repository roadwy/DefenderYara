
rule Ransom_Win32_Maze_PB_MTB{
	meta:
		description = "Ransom:Win32/Maze.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_02_0 = {0f b6 06 46 85 c0 74 90 01 01 bb 00 00 00 00 23 d3 21 5d 90 01 01 83 45 90 01 01 08 d1 c0 8a fc 8a e6 d1 cb ff 4d 90 01 01 75 90 01 01 6a 00 89 0c 24 33 c9 33 cb 8b c1 59 aa 49 75 90 00 } //1
		$a_02_1 = {0f b6 06 46 85 c0 74 90 01 01 bb 00 00 00 00 23 d3 21 5d fc 83 45 fc 08 d1 c0 8a fc 8a e6 d1 cb ff 4d fc 75 90 01 01 6a 00 89 14 24 2b d2 33 d3 8b c2 5a aa 49 75 90 00 } //1
		$a_02_2 = {0f b6 1c 30 6a 00 89 3c 24 2b ff 33 7d 90 01 01 8b d7 5f d3 c2 23 d3 ac 0a c2 88 07 47 ff 4d 90 01 01 75 90 00 } //1
		$a_02_3 = {0f b6 1c 30 6a 00 89 34 24 33 f6 03 75 90 01 01 8b d6 5e d3 c2 23 d3 ac 0a c2 88 07 47 ff 4d f8 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1) >=2
 
}