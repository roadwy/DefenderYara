
rule VirTool_WinNT_Cutwail_gen_F{
	meta:
		description = "VirTool:WinNT/Cutwail.gen!F,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {85 c9 74 0b 31 06 83 c6 04 c1 c0 03 49 eb f1 } //01 00 
		$a_03_1 = {c7 80 04 04 00 00 90 01 04 8b 45 fc 0f 22 c0 fb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}