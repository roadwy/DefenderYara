
rule VirTool_WinNT_Koobface_gen_F{
	meta:
		description = "VirTool:WinNT/Koobface.gen!F,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {2d 87 00 00 00 74 0f 48 48 74 0b 48 48 74 07 2d 32 01 00 00 75 07 8b c3 83 e0 fd } //01 00 
		$a_00_1 = {5c 57 5a 53 2e 70 64 62 } //01 00 
		$a_00_2 = {3a 5c 64 6e 73 62 6c 6f 63 6b 65 72 5c } //00 00 
	condition:
		any of ($a_*)
 
}