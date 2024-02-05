
rule VirTool_WinNT_Hackdef_gen_C{
	meta:
		description = "VirTool:WinNT/Hackdef.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {57 8b 7d 0c 8b 47 60 8b 48 04 89 0d 90 01 02 01 00 8b 40 0c 8b 77 0c 33 db 2d 00 20 22 00 89 9d f0 fb ff ff 0f 84 90 01 01 01 00 00 6a 04 59 2b c1 74 90 01 01 89 1e 89 4f 1c c7 90 02 05 10 00 00 c0 e9 90 01 02 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}