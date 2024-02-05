
rule VirTool_WinNT_Hackdef_gen_H{
	meta:
		description = "VirTool:WinNT/Hackdef.gen!H,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {52 50 ff 15 90 01 02 01 00 89 45 f8 c7 45 fc dc 05 01 00 8b 45 f8 8b 18 89 1d 28 0a 01 00 8b 5d fc 89 18 6a 04 ff 75 f8 ff 15 90 01 02 01 00 8b 45 f4 83 c0 04 6a 04 50 8d 45 fc 50 ff d6 83 c4 0c 6a 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}