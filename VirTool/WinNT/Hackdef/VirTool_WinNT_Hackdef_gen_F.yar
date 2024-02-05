
rule VirTool_WinNT_Hackdef_gen_F{
	meta:
		description = "VirTool:WinNT/Hackdef.gen!F,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {83 c0 f4 66 89 01 eb 90 00 } //01 00 
		$a_02_1 = {85 c0 0f 8c 90 01 01 00 00 00 8b 85 90 01 01 fb ff ff 66 83 38 05 75 90 01 01 66 83 78 02 70 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}