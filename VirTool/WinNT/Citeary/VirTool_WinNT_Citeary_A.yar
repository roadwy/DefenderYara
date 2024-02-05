
rule VirTool_WinNT_Citeary_A{
	meta:
		description = "VirTool:WinNT/Citeary.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {5c 00 44 00 6f 00 73 00 44 00 65 00 76 00 69 00 63 00 65 00 73 00 5c 00 49 00 63 00 79 00 48 00 65 00 61 00 72 00 74 00 } //01 00 
		$a_01_1 = {63 3a 5c 75 73 65 72 73 5c 69 63 79 68 65 61 72 74 5c } //01 00 
		$a_01_2 = {fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 8b 03 89 04 8a 0f 20 c0 0d 00 00 01 00 0f 22 c0 fb eb 71 } //00 00 
	condition:
		any of ($a_*)
 
}