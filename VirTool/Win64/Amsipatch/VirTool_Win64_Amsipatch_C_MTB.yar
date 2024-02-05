
rule VirTool_Win64_Amsipatch_C_MTB{
	meta:
		description = "VirTool:Win64/Amsipatch.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {c7 01 44 31 52 4b 90 90 } //01 00 
		$a_02_1 = {41 b9 04 00 00 00 48 89 44 24 20 4c 8d 90 01 02 48 c7 45 c7 00 10 00 00 48 8d 90 01 02 48 89 5d b7 48 8b cf ff 15 90 00 } //01 00 
		$a_02_2 = {48 c7 44 24 20 00 00 00 00 4c 8d 90 01 02 48 8b d3 48 8b cf ff 15 90 00 } //01 00 
		$a_02_3 = {44 8b 4d bf 48 8d 90 01 02 4c 8d 90 01 02 48 89 44 24 20 48 8d 90 01 02 48 8b cf ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}