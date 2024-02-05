
rule VirTool_WinNT_Rootkitdrv_gen_FK{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.gen!FK,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {e8 00 00 00 00 58 83 e8 05 2d 90 01 04 03 45 08 89 45 fc 8b 45 fc 8b e5 5d c2 04 00 90 00 } //01 00 
		$a_00_1 = {e8 00 00 00 00 58 83 c0 05 c3 } //01 00 
		$a_00_2 = {e8 00 00 00 00 58 83 e8 05 89 45 d8 8b 45 d8 2d b7 14 00 00 89 45 e4 8b 4d fc 2b 4d e4 83 c1 34 89 4d e8 } //00 00 
	condition:
		any of ($a_*)
 
}