
rule VirTool_WinNT_Rovnix_C{
	meta:
		description = "VirTool:WinNT/Rovnix.C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {81 7d 08 03 00 00 80 75 90 01 01 eb 09 8b 45 fc 83 c0 01 89 45 fc 83 7d fc 01 73 90 01 01 8b 4d fc 83 3c 8d 90 01 04 00 90 00 } //01 00 
		$a_03_1 = {83 f8 2a 74 0d 0f b6 4d ff 83 f9 3b 0f 85 90 01 04 8b 55 f4 52 8b 45 e4 50 8b 4d e0 51 e8 90 01 04 85 c0 0f 84 90 01 04 c7 45 f8 22 00 00 c0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}