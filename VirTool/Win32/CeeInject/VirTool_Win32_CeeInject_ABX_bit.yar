
rule VirTool_Win32_CeeInject_ABX_bit{
	meta:
		description = "VirTool:Win32/CeeInject.ABX!bit,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {8b c1 83 e0 03 0f b6 44 04 90 01 01 30 81 90 01 04 8d 82 90 01 04 03 c1 83 e0 03 0f b6 44 04 90 01 01 30 81 90 01 04 8d 86 90 01 04 03 c1 83 e0 03 0f b6 44 04 90 01 01 30 81 90 01 04 8d 87 90 01 04 03 c1 83 e0 03 0f b6 44 04 90 01 01 30 81 90 00 } //02 00 
		$a_03_1 = {33 c9 81 ea 90 01 04 81 ee 90 01 04 81 ef 90 00 } //01 00 
		$a_01_2 = {88 4c 24 0f 34 79 80 74 24 0f da 80 7c 24 0f e9 75 10 3c 40 75 0c 80 7c 24 10 31 75 05 80 fa 38 74 16 41 8b d1 8b c1 c1 ea 10 89 54 24 10 8b d1 c1 e8 08 c1 ea 18 eb c8 } //01 00 
		$a_01_3 = {88 44 24 0f 80 f1 79 80 74 24 0f da 80 7c 24 0f e9 75 0f 80 f9 40 75 0a 80 fb 31 75 05 80 fa 38 74 12 40 8b c8 8b d8 8b d0 c1 e9 08 c1 eb 10 c1 ea 18 eb cc } //00 00 
	condition:
		any of ($a_*)
 
}