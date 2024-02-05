
rule VirTool_WinNT_Xooba_A{
	meta:
		description = "VirTool:WinNT/Xooba.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {6a 00 6a 00 6a 00 6a 01 6a 07 6a 00 6a 00 8d 90 01 03 50 8d 90 01 03 50 68 81 00 00 00 8d 90 01 03 50 90 00 } //01 00 
		$a_02_1 = {03 c0 01 43 0c 8b 43 0c 33 d2 f7 35 90 01 03 00 8b c2 85 c0 76 0b 90 00 } //01 00 
		$a_00_2 = {4e 00 54 00 46 00 53 00 } //00 00 
	condition:
		any of ($a_*)
 
}