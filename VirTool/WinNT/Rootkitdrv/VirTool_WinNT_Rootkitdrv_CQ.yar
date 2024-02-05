
rule VirTool_WinNT_Rootkitdrv_CQ{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.CQ,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {0f b7 00 3d 93 08 00 00 } //02 00 
		$a_01_1 = {74 66 3d 28 0a 00 00 74 35 3d ce 0e 00 00 74 04 32 c0 } //02 00 
		$a_01_2 = {fa 0f 20 c0 89 44 24 00 25 ff ff fe ff 0f 22 c0 8b 01 } //02 00 
		$a_01_3 = {66 83 38 21 75 05 66 c7 00 5c 00 } //01 00 
		$a_01_4 = {4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65 } //01 00 
		$a_01_5 = {4e 74 42 75 69 6c 64 4e 75 6d 62 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}