
rule VirTool_WinNT_Rovnix_B{
	meta:
		description = "VirTool:WinNT/Rovnix.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {81 3c 01 13 13 13 13 74 08 40 } //1
		$a_01_1 = {81 3b 03 00 00 80 57 8b 7d 14 75 0f 56 8d b7 b8 00 00 00 e8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}