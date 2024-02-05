
rule VirTool_Win32_CeeInject_ABM_bit{
	meta:
		description = "VirTool:Win32/CeeInject.ABM!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b7 fb e8 90 01 04 8b 4e 04 03 c7 8a 14 08 32 d3 32 16 43 88 54 3c 90 01 01 66 3b 5e 02 72 e1 90 00 } //01 00 
		$a_03_1 = {0f b7 de e8 90 01 04 8b 4f 04 03 c3 66 0f be 14 08 0f b6 07 66 33 d0 66 33 d6 b9 90 01 04 66 23 d1 46 66 89 54 5d 00 66 3b 77 02 72 d1 90 00 } //01 00 
		$a_03_2 = {03 f2 81 e6 90 01 04 79 08 4e 81 ce 90 01 04 46 8b 5c b4 90 01 01 0f b6 d2 89 5c 8c 90 01 01 89 54 b4 90 01 01 8b 5c 8c 90 01 01 03 da 81 e3 90 01 04 79 08 4b 81 cb 90 01 04 43 0f b6 54 9c 90 01 01 30 14 38 40 3b c5 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}