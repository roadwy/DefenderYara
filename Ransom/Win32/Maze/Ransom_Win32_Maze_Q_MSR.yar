
rule Ransom_Win32_Maze_Q_MSR{
	meta:
		description = "Ransom:Win32/Maze.Q!MSR,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {4b 69 6c 6c 79 6f 75 72 73 65 6c 66 2e 64 6c 6c } //01 00 
		$a_01_1 = {77 63 68 43 72 79 70 74 33 32 } //01 00 
		$a_01_2 = {64 77 53 68 65 6c 6c 43 6f 64 65 53 69 7a 65 } //00 00 
		$a_00_3 = {5d 04 00 } //00 6f 
	condition:
		any of ($a_*)
 
}