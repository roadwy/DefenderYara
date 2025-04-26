
rule VirTool_WinNT_Rovnix_D{
	meta:
		description = "VirTool:WinNT/Rovnix.D,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {83 c6 14 b8 46 4a 00 00 66 39 06 0f 84 6b ff ff ff } //1
		$a_01_1 = {8d 74 86 14 b8 46 4a 00 00 66 39 06 0f 84 } //1
		$a_03_2 = {ff 3c 2a 74 ?? 3c 3b 74 ?? 3c 28 74 04 3c 3c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}