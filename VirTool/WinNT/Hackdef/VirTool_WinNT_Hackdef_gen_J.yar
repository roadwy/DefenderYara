
rule VirTool_WinNT_Hackdef_gen_J{
	meta:
		description = "VirTool:WinNT/Hackdef.gen!J,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 7d 0c 31 db 8b 47 60 89 5d f4 8b 48 04 89 0d 84 08 01 00 8b 40 0c 8b 77 0c 2d 00 20 22 00 0f 84 ?? 00 00 00 6a 04 59 29 c8 74 ?? 89 1e 89 4f 1c c7 45 f4 10 00 00 c0 e9 ?? ?? 00 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}