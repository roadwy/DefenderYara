
rule VirTool_Win64_Injecdlz_A_MTB{
	meta:
		description = "VirTool:Win64/Injecdlz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {41 b8 c4 11 00 00 33 d2 b9 ff ff 1f 00 ff 90 01 05 48 89 45 08 48 83 7d 08 00 75 1e 90 00 } //01 00 
		$a_02_1 = {41 b9 00 30 00 00 41 b8 04 01 00 00 33 d2 48 8b 4d 08 ff 90 01 05 48 89 45 28 48 83 7d 28 00 75 1e 90 00 } //01 00 
		$a_00_2 = {b9 08 00 00 00 48 6b c9 01 48 c7 44 24 20 00 00 00 00 4c 8b c8 48 8b 85 88 01 00 00 4c 8b 04 08 48 8b 55 28 48 8b 4d 08 ff } //01 00 
		$a_00_3 = {48 c7 44 24 30 00 00 00 00 c7 44 24 28 00 00 00 00 48 8b 45 28 48 89 44 24 20 4c 8b 8d 88 00 00 00 45 33 c0 33 d2 48 8b 4d 08 ff } //00 00 
	condition:
		any of ($a_*)
 
}