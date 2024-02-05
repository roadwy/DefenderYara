
rule HackTool_Win64_Zenbleed_A_dha{
	meta:
		description = "HackTool:Win64/Zenbleed.A!dha,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {c5 fc 77 48 31 c0 48 0f 6e c0 } //01 00 
		$a_01_1 = {48 ff c9 66 0f 2a e0 66 0f 2a d8 66 0f 2a d0 66 0f 2a c8 66 0f 2a c0 c5 fd 6f c0 78 03 c5 f8 77 } //00 00 
	condition:
		any of ($a_*)
 
}