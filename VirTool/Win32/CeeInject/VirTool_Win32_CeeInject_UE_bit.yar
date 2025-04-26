
rule VirTool_Win32_CeeInject_UE_bit{
	meta:
		description = "VirTool:Win32/CeeInject.UE!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {4f 0f b6 d8 8a 54 1c ?? 0f b6 c2 03 c6 0f b6 f0 8a 44 34 ?? 88 44 1c ?? 88 54 34 ?? 0f b6 4c 1c ?? 0f b6 c2 03 c8 81 e1 ?? ?? ?? ?? 79 08 49 81 c9 ?? ?? ?? ?? 41 8a 4c 0c ?? 30 4d 00 45 85 ff 75 } //1
		$a_01_1 = {64 a1 30 00 00 00 8b 40 0c 8b 40 14 8b 00 8b 00 8b 40 10 } //1
		$a_03_2 = {33 d2 8a 5c 3c ?? 8b c7 f7 f6 0f b6 04 0a 03 c5 0f b6 cb 03 c8 0f b6 e9 8b 4c 24 ?? 8a 44 2c ?? 88 44 3c ?? 47 88 5c 2c ?? 81 ff 00 01 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}