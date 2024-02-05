
rule VirTool_Win32_CeeInject_AAC_bit{
	meta:
		description = "VirTool:Win32/CeeInject.AAC!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 00 8b 0d 90 01 04 c1 e8 03 85 c0 76 14 56 57 8b f1 8b f8 90 00 } //01 00 
		$a_03_1 = {8b f2 c1 ee 05 03 35 90 01 04 8b fa c1 e7 04 03 3d 90 01 04 33 f7 8d 3c 10 33 f7 2b ce 8b f1 c1 ee 05 03 35 90 01 04 8b f9 c1 e7 04 03 3d 90 01 04 33 f7 8d 3c 08 33 f7 2b d6 05 90 01 04 ff 4d fc 75 b8 8b 45 08 5f 89 10 89 48 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}