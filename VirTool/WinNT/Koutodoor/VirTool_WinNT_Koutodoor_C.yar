
rule VirTool_WinNT_Koutodoor_C{
	meta:
		description = "VirTool:WinNT/Koutodoor.C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {2d 04 20 22 00 0f 84 90 01 04 2d ff c0 00 00 74 90 01 01 83 e8 3d 74 90 00 } //01 00 
		$a_00_1 = {5c 41 70 73 58 38 35 2e 70 64 62 } //00 00  \ApsX85.pdb
	condition:
		any of ($a_*)
 
}