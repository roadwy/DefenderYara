
rule Ransom_Win32_Maze_ARA_MTB{
	meta:
		description = "Ransom:Win32/Maze.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {e9 0c 01 00 00 c6 45 e4 43 c6 45 e5 72 c6 45 e6 79 c6 45 e7 70 c6 45 e8 74 c6 45 e9 53 c6 45 ea 74 c6 45 eb 72 c6 45 ec 69 c6 45 ed 6e c6 45 ee 67 c6 45 ef 54 c6 45 f0 6f c6 45 f1 42 c6 45 f2 69 c6 45 f3 6e c6 45 f4 61 c6 45 f5 72 c6 45 f6 79 c6 45 f7 41 c6 45 f8 00 8d 4d e4 51 8b 55 b8 52 } //00 00 
	condition:
		any of ($a_*)
 
}