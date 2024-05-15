
rule VirTool_Win64_Chai_A{
	meta:
		description = "VirTool:Win64/Chai.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 8b ce ff 90 01 05 48 8b 55 f7 90 01 07 44 8b c0 90 01 05 48 8b 55 f7 45 33 c9 45 33 c0 4c 89 7c 24 20 48 8b ce 90 00 } //01 00 
		$a_01_1 = {48 89 4c 24 08 48 89 54 24 10 4c 89 44 24 18 4c 89 4c 24 20 53 56 57 48 83 ec 30 48 8b f9 } //01 00 
		$a_03_2 = {48 89 5c 24 38 44 8d 43 50 89 5c 24 30 90 01 07 c7 44 24 28 03 00 00 00 45 33 c9 48 8b c8 48 89 5c 24 20 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}