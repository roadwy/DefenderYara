
rule VirTool_WinNT_Cutwail_gen_E{
	meta:
		description = "VirTool:WinNT/Cutwail.gen!E,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {81 38 ee dd cc bb 75 0f ff 75 0c ff 75 08 } //02 00 
		$a_01_1 = {85 c0 76 0c 80 b1 90 01 05 41 3b c8 72 f4 } //01 00 
		$a_01_2 = {83 c1 38 56 8b 55 0c 8b 14 82 8b f1 87 16 40 83 c1 04 } //01 00 
		$a_01_3 = {68 4e 72 74 6b } //01 00  hNrtk
		$a_03_4 = {74 2f 8b 46 18 83 c0 30 50 e8 90 01 02 ff ff 85 c0 74 1f be 22 00 00 c0 90 00 } //01 00 
		$a_01_5 = {6e 64 69 73 5f 76 65 72 } //00 00  ndis_ver
	condition:
		any of ($a_*)
 
}