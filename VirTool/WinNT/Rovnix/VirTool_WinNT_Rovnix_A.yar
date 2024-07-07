
rule VirTool_WinNT_Rovnix_A{
	meta:
		description = "VirTool:WinNT/Rovnix.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {66 3d 46 4a 74 17 66 8b 46 10 83 c6 10 66 85 c0 75 ee 66 81 3e 46 4a } //1
		$a_01_1 = {8b 54 24 04 85 d2 b8 0d 00 00 c0 74 13 8b 4c 24 10 85 c9 74 1a 8b 44 24 08 50 52 ff d1 c2 10 00 8b 4c 24 0c 85 c9 74 07 8b 54 24 08 52 ff d1 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}