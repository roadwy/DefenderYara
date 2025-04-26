
rule Ransom_Win32_Maze_PS_MTB{
	meta:
		description = "Ransom:Win32/Maze.PS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {8b c3 2b fb 8d 5d ?? 2b 5d ?? eb 07 8d a4 24 ?? ?? ?? ?? 8a 0c 03 8d 40 ?? 32 4c 07 ?? 88 48 ?? 4a 75 } //2
		$a_00_1 = {43 61 72 64 65 72 73 4c 69 76 65 4d 61 74 74 65 72 2e 70 64 62 } //1 CardersLiveMatter.pdb
		$a_00_2 = {67 66 67 39 75 72 77 79 66 37 2e 70 64 62 } //1 gfg9urwyf7.pdb
	condition:
		((#a_02_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}