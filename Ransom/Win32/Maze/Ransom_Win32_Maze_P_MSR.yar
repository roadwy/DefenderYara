
rule Ransom_Win32_Maze_P_MSR{
	meta:
		description = "Ransom:Win32/Maze.P!MSR,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 00 3a 00 5c 00 4a 00 44 00 55 00 49 00 48 00 69 00 75 00 66 00 5c 00 49 00 44 00 69 00 73 00 6a 00 6f 00 70 00 6a 00 63 00 6e 00 62 00 } //01 00  C:\JDUIHiuf\IDisjopjcnb
		$a_00_1 = {6b 69 6c 6c 5c 79 6f 75 72 73 65 6c 66 5c 40 59 6f 6e 67 72 75 69 54 61 6e 5c 63 68 69 6e 65 73 65 5c 69 64 69 6f 74 2e 70 64 62 } //01 00  kill\yourself\@YongruiTan\chinese\idiot.pdb
		$a_01_2 = {79 00 6f 00 75 00 20 00 6f 00 75 00 72 00 20 00 6a 00 6f 00 62 00 20 00 61 00 6c 00 73 00 6f 00 20 00 77 00 6f 00 75 00 6c 00 64 00 20 00 62 00 65 00 20 00 66 00 75 00 63 00 6b 00 69 00 6e 00 67 00 20 00 62 00 6f 00 72 00 69 00 6e 00 67 00 20 00 61 00 73 00 20 00 68 00 65 00 6c 00 6c 00 } //01 00  you our job also would be fucking boring as hell
		$a_01_3 = {44 00 6a 00 44 00 6a 00 64 00 66 00 6f 00 64 00 67 00 73 00 } //00 00  DjDjdfodgs
	condition:
		any of ($a_*)
 
}