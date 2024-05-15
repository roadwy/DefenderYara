
rule VirTool_Win64_Excheposez_A_MTB{
	meta:
		description = "VirTool:Win64/Excheposez.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 8b 7d a0 48 83 ff 06 90 01 06 4c 8b c7 90 02 12 85 c0 90 01 06 33 d2 41 b8 00 01 00 00 90 02 12 33 d2 41 b8 00 01 00 00 90 02 12 33 ff 89 7c 24 78 90 02 16 48 8b c8 90 01 04 ba ff 01 0f 00 90 00 } //01 00 
		$a_03_1 = {48 89 7d d7 0f 57 c0 0f 11 45 e7 48 89 7d f7 48 c7 45 ff 0f 00 00 00 40 88 7d e7 0f 11 45 07 48 89 7d 17 48 c7 45 1f 07 00 00 00 66 89 7d 07 90 01 08 bb 01 00 00 00 8b d3 33 c9 90 01 06 85 c0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}