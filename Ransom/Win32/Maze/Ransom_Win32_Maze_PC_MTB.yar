
rule Ransom_Win32_Maze_PC_MTB{
	meta:
		description = "Ransom:Win32/Maze.PC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 0f 8b f1 8b 57 ?? 8d 7f 04 c1 c6 0f 8b c1 c1 c0 0d 33 f0 c1 e9 0a 33 f1 8b c2 8b ca c1 c8 07 c1 c1 0e 33 c8 c1 ea 03 33 ca 03 f1 03 77 ?? 03 77 ?? 03 f3 43 89 77 04 81 fb ?? ?? 00 00 72 } //20
		$a_02_1 = {c1 c0 09 0f b6 8e ?? ?? 00 00 c1 ca 0a 33 d0 8b 86 ?? ?? 00 00 c1 c8 08 03 d0 0f b6 86 ?? ?? 00 00 03 54 be 04 8b 84 86 ?? ?? 00 00 03 84 8e ?? ?? 00 00 33 d0 89 54 be 04 89 96 ?? ?? 00 00 8b 44 be 0c 8b 96 ?? ?? 00 00 0f b6 8e ?? ?? 00 00 } //1
	condition:
		((#a_02_0  & 1)*20+(#a_02_1  & 1)*1) >=21
 
}