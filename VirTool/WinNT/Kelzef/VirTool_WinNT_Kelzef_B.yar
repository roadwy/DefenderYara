
rule VirTool_WinNT_Kelzef_B{
	meta:
		description = "VirTool:WinNT/Kelzef.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {4d 65 54 65 72 76 69 63 65 45 65 73 63 72 69 71 74 6f 72 54 61 62 6c 65 } //01 00 
		$a_02_1 = {5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 52 00 6f 00 6f 00 74 00 90 01 26 74 00 63 00 5c 00 68 00 6f 00 73 00 74 00 73 00 90 00 } //01 00 
		$a_00_2 = {73 76 63 68 6f 73 74 2e 65 78 65 00 69 65 78 70 6c 6f 72 65 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}