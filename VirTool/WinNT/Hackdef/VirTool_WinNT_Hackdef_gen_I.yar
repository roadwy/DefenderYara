
rule VirTool_WinNT_Hackdef_gen_I{
	meta:
		description = "VirTool:WinNT/Hackdef.gen!I,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 5d 0c 56 57 8b 43 60 6a 01 5e 89 35 c4 09 01 00 8b 48 04 89 0d c8 09 01 00 89 35 c4 09 01 00 8b 40 0c 89 35 c4 09 01 00 8b 7b 0c 33 c9 2d 00 20 22 00 89 4d f8 89 35 90 01 02 01 00 0f 84 90 01 01 01 00 00 6a 04 5a 2b c2 74 90 01 01 89 0f 89 53 1c c7 45 f8 10 00 00 c0 e9 90 01 01 02 00 00 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}