
rule VirTool_Win64_Hidesz_A_MTB{
	meta:
		description = "VirTool:Win64/Hidesz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 89 c7 f3 a4 4c 89 ee 48 8b 44 24 58 48 63 4c 24 54 48 8b 40 10 48 89 c7 f3 a4 48 8b 44 24 58 4c 8b 6d 00 48 8d 90 01 05 48 89 18 48 8d 90 01 05 e8 e1 90 00 } //01 00 
		$a_03_1 = {49 8b 0e 48 89 c2 e8 ea 90 01 03 85 c0 0f 84 fb 05 00 00 49 8b 0e 49 8b 56 20 4c 8d 90 01 05 49 90 01 03 e8 03 90 00 } //01 00 
		$a_03_2 = {49 8b 06 45 31 ff 49 8b 4e 10 45 31 c9 4c 89 7c 24 28 45 31 c0 31 d2 c7 44 24 20 00 00 00 10 ff 90 01 05 49 89 46 38 48 85 c0 75 90 00 } //01 00 
		$a_03_3 = {48 89 fa 48 89 c6 49 8b 06 48 89 f1 ff 90 01 05 49 8b 06 48 8b 54 24 68 48 89 f9 ff 90 01 05 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}