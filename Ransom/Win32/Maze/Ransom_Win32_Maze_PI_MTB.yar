
rule Ransom_Win32_Maze_PI_MTB{
	meta:
		description = "Ransom:Win32/Maze.PI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 4d b8 83 c1 01 89 4d b8 8b 55 b8 3b 55 18 73 90 02 04 8b 45 90 01 01 03 45 b8 0f b6 08 8b 55 b8 0f b6 44 15 bc 33 c8 8b 55 14 03 55 b8 88 0a eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Ransom_Win32_Maze_PI_MTB_2{
	meta:
		description = "Ransom:Win32/Maze.PI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 06 00 04 00 00 03 00 "
		
	strings :
		$a_02_0 = {8b 4d b8 83 c1 01 89 4d b8 8b 55 b8 3b 55 18 73 90 02 04 8b 45 90 01 01 03 45 b8 0f b6 08 8b 55 b8 0f b6 44 15 bc 33 c8 8b 55 14 03 55 b8 88 0a eb 90 00 } //03 00 
		$a_01_1 = {79 6f 75 61 72 65 6d 79 73 68 61 6d 65 21 21 } //01 00 
		$a_01_2 = {5c 72 61 6e 73 6f 6d 77 61 72 65 5c 68 75 74 63 68 69 6e 73 2e 70 64 62 } //01 00 
		$a_01_3 = {5c 66 75 63 6b 69 6e 67 5c 69 64 69 6f 74 69 63 5c 6e 6f 6e 65 78 69 73 74 69 6e 67 5c 66 69 6c 65 5c 77 69 74 68 5c 70 64 62 5c 65 78 74 65 6e 73 69 6f 6e 2e 70 64 62 } //00 00 
		$a_00_4 = {5d 04 00 00 ab 23 } //04 80 
	condition:
		any of ($a_*)
 
}