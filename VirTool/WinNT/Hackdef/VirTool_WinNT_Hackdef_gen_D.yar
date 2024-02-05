
rule VirTool_WinNT_Hackdef_gen_D{
	meta:
		description = "VirTool:WinNT/Hackdef.gen!D,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {52 50 ff 15 90 01 01 06 01 00 89 45 f8 c7 45 fc 90 01 01 04 01 00 8b 45 f8 8b 18 89 1d 90 01 01 07 01 00 8b 5d fc 89 18 6a 04 ff 75 f8 ff 15 90 01 01 06 01 00 8b 45 f4 6a 04 83 c0 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}