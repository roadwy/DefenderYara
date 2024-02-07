
rule VirTool_WinNT_Emold_C{
	meta:
		description = "VirTool:WinNT/Emold.C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {5e 73 44 7d 6b 6c 72 7f 78 5a } //02 00  獞組汫署婸
		$a_01_1 = {8b b4 3b a0 00 00 00 03 df 68 } //01 00 
		$a_01_2 = {30 14 30 40 3b c1 7c } //01 00 
		$a_01_3 = {30 14 30 83 c0 01 3b c1 7c } //00 00 
	condition:
		any of ($a_*)
 
}