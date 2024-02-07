
rule VirTool_WinNT_Cutwail_gen_D{
	meta:
		description = "VirTool:WinNT/Cutwail.gen!D,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {66 3d 28 0a 73 09 83 25 90 01 04 00 eb 0c 75 0a c7 05 90 01 04 64 01 00 00 90 00 } //02 00 
		$a_03_1 = {ff 73 fc 8b 03 05 90 01 04 50 8b 43 f8 03 45 dc 50 e8 90 01 02 ff ff 83 c3 28 ff 45 e0 0f b7 46 06 39 45 e0 7c da 90 00 } //01 00 
		$a_01_2 = {8b 46 28 03 45 } //01 00 
		$a_01_3 = {68 4e 72 74 6b } //00 00  hNrtk
	condition:
		any of ($a_*)
 
}