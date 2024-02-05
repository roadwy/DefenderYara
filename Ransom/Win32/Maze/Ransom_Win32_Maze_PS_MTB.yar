
rule Ransom_Win32_Maze_PS_MTB{
	meta:
		description = "Ransom:Win32/Maze.PS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_02_0 = {8b c3 2b fb 8d 5d 90 01 01 2b 5d 90 01 01 eb 07 8d a4 24 90 01 04 8a 0c 03 8d 40 90 01 01 32 4c 07 90 01 01 88 48 90 01 01 4a 75 90 00 } //01 00 
		$a_00_1 = {43 61 72 64 65 72 73 4c 69 76 65 4d 61 74 74 65 72 2e 70 64 62 } //01 00 
		$a_00_2 = {67 66 67 39 75 72 77 79 66 37 2e 70 64 62 } //00 00 
		$a_00_3 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}