
rule VirTool_WinNT_Rovnix_D{
	meta:
		description = "VirTool:WinNT/Rovnix.D,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {83 c6 14 b8 46 4a 00 00 66 39 06 0f 84 6b ff ff ff } //01 00 
		$a_01_1 = {8d 74 86 14 b8 46 4a 00 00 66 39 06 0f 84 } //01 00 
		$a_03_2 = {ff 3c 2a 74 90 01 01 3c 3b 74 90 01 01 3c 28 74 04 3c 3c 90 00 } //00 00 
		$a_00_3 = {5d } //04 00 
	condition:
		any of ($a_*)
 
}