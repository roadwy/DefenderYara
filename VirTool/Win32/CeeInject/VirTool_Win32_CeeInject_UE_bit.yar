
rule VirTool_Win32_CeeInject_UE_bit{
	meta:
		description = "VirTool:Win32/CeeInject.UE!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {4f 0f b6 d8 8a 54 1c 90 01 01 0f b6 c2 03 c6 0f b6 f0 8a 44 34 90 01 01 88 44 1c 90 01 01 88 54 34 90 01 01 0f b6 4c 1c 90 01 01 0f b6 c2 03 c8 81 e1 90 01 04 79 08 49 81 c9 90 01 04 41 8a 4c 0c 90 01 01 30 4d 00 45 85 ff 75 90 00 } //01 00 
		$a_01_1 = {64 a1 30 00 00 00 8b 40 0c 8b 40 14 8b 00 8b 00 8b 40 10 } //01 00 
		$a_03_2 = {33 d2 8a 5c 3c 90 01 01 8b c7 f7 f6 0f b6 04 0a 03 c5 0f b6 cb 03 c8 0f b6 e9 8b 4c 24 90 01 01 8a 44 2c 90 01 01 88 44 3c 90 01 01 47 88 5c 2c 90 01 01 81 ff 00 01 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}