
rule VirTool_WinNT_Hackdef_gen_F{
	meta:
		description = "VirTool:WinNT/Hackdef.gen!F,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {83 c0 f4 66 89 01 eb } //1
		$a_02_1 = {85 c0 0f 8c ?? 00 00 00 8b 85 ?? fb ff ff 66 83 38 05 75 ?? 66 83 78 02 70 75 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}