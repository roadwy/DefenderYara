
rule Ransom_Win32_Maze_B_MSR{
	meta:
		description = "Ransom:Win32/Maze.B!MSR,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 74 65 67 2e 67 70 5c 66 73 73 64 66 2e 70 64 62 } //01 00  \teg.gp\fssdf.pdb
		$a_01_1 = {46 00 69 00 6c 00 65 00 20 00 73 00 65 00 72 00 76 00 65 00 73 00 20 00 61 00 73 00 20 00 61 00 20 00 64 00 72 00 69 00 76 00 65 00 72 00 20 00 6f 00 66 00 20 00 4e 00 6f 00 72 00 74 00 68 00 20 00 4b 00 6f 00 72 00 65 00 61 00 20 00 50 00 6f 00 77 00 65 00 72 00 } //00 00  File serves as a driver of North Korea Power
	condition:
		any of ($a_*)
 
}