
rule VirTool_WinNT_Hackdef_gen_E{
	meta:
		description = "VirTool:WinNT/Hackdef.gen!E,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {2d 00 20 22 00 89 ?? ?? 0f 84 ?? ?? 00 00 6a 04 59 2b c1 74 ?? 89 ?? 89 ?? 1c c7 45 ?? 10 00 00 c0 e9 ?? 01 00 00 8b 06 8b 56 04 89 ?? 89 45 ?? 8d 45 ?? 50 8d 45 ?? 50 68 ff 0f 1f 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}