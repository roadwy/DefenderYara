
rule VirTool_WinNT_Rootkitdrv_LQ{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.LQ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {81 6d f4 04 00 61 25 0f 84 90 01 04 83 6d f4 04 74 90 01 01 83 6d f4 04 74 90 00 } //01 00 
		$a_03_1 = {8b 45 18 8b 40 04 33 d2 6a 14 59 f7 f1 89 45 90 01 01 8b 45 28 89 45 90 01 01 83 65 90 01 01 00 eb 07 8b 45 90 01 01 40 89 45 90 01 01 8b 45 90 01 01 3b 45 90 01 01 0f 83 90 01 02 00 00 83 3d 90 01 04 00 74 90 01 01 8b 45 90 01 01 6b c0 14 8b 4d 90 01 01 8b 44 01 0c 3b 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}