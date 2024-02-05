
rule VirTool_Win64_Amseosz_A_MTB{
	meta:
		description = "VirTool:Win64/Amseosz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 8b c8 48 8d 90 01 05 ff 15 90 01 04 0f 57 c0 48 8d 90 01 05 48 8b d8 48 8d 90 01 03 33 c0 89 84 90 00 } //01 00 
		$a_03_1 = {48 89 44 24 30 4c 8d 90 01 03 48 8d 90 01 03 41 b9 04 00 00 00 48 8d 90 01 03 48 89 44 24 20 48 8b cf ff 15 90 00 } //01 00 
		$a_03_2 = {41 b9 01 00 00 00 48 c7 44 24 20 00 00 00 00 4c 8d 90 01 03 48 8b cf ff 15 90 00 } //01 00 
		$a_03_3 = {48 8b 4a 08 48 89 bc 24 d0 00 00 00 ff 15 90 01 04 33 d2 44 8b c0 8d 90 01 02 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}