
rule Ransom_Win32_Maze_GG_MTB{
	meta:
		description = "Ransom:Win32/Maze.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_80_0 = {77 63 68 43 72 79 70 74 33 32 } //wchCrypt32  01 00 
		$a_80_1 = {64 77 53 68 65 6c 6c 43 6f 64 65 53 69 7a 65 } //dwShellCodeSize  01 00 
		$a_80_2 = {6b 65 79 73 74 72 65 61 6d } //keystream  01 00 
		$a_80_3 = {66 6e 4e 61 6d 65 } //fnName  01 00 
		$a_81_4 = {50 44 42 4f 70 65 6e 56 61 6c 69 64 61 74 65 35 } //01 00  PDBOpenValidate5
		$a_80_5 = {44 6c 6c 49 6e 73 74 61 6c 6c } //DllInstall  01 00 
		$a_80_6 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //DllRegisterServer  01 00 
		$a_80_7 = {2e 70 64 62 } //.pdb  00 00 
	condition:
		any of ($a_*)
 
}