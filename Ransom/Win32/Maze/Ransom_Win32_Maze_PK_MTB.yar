
rule Ransom_Win32_Maze_PK_MTB{
	meta:
		description = "Ransom:Win32/Maze.PK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {2b f0 2b f8 8d 4c 24 ?? 03 ca 8a 04 0e 32 01 42 88 04 0f 3b d3 72 } //1
		$a_00_1 = {33 44 24 14 89 07 8b 46 04 33 44 24 18 89 47 04 8b 46 08 33 44 24 1c 89 47 08 8b 46 0c 33 44 24 20 89 47 0c 8b 46 10 33 44 24 24 89 47 10 8b 46 14 33 44 24 28 89 47 14 8b 46 18 33 44 24 2c } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}