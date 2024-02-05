
rule VirTool_WinNT_Rootkitdrv_gen_FR{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.gen!FR,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 03 00 00 0a 00 "
		
	strings :
		$a_02_0 = {c7 45 c4 00 00 00 00 c7 45 c8 00 00 00 00 c7 45 fc 00 00 00 00 6a 04 6a 04 8b 4d d0 51 ff 15 90 01 04 6a 04 6a 04 8b 55 dc 52 ff 15 90 01 04 c7 45 fc ff ff ff ff 90 00 } //0a 00 
		$a_00_1 = {8b 45 ec 8b 08 8b 11 89 55 c0 b8 01 00 00 00 c3 } //0a 00 
		$a_00_2 = {8b 65 e8 8b 45 c0 89 45 d4 c7 45 fc ff ff ff ff eb } //00 00 
	condition:
		any of ($a_*)
 
}