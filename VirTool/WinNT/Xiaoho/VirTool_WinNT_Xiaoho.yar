
rule VirTool_WinNT_Xiaoho{
	meta:
		description = "VirTool:WinNT/Xiaoho,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {5c 44 6f 73 44 65 76 69 63 65 73 5c 4b 50 44 72 76 4c 4e 31 } //01 00 
		$a_00_1 = {48 41 4c 2e 64 6c 6c } //01 00 
		$a_02_2 = {83 ec 40 56 57 c7 90 01 02 10 00 00 c0 90 02 40 81 90 01 02 c0 20 22 00 74 05 e9 b1 00 00 00 90 00 } //01 00 
		$a_02_3 = {56 64 a1 24 c7 45 90 01 01 01 00 00 8b c7 45 90 01 01 74 24 08 3b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}