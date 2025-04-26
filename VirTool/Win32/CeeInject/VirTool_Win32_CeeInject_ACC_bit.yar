
rule VirTool_Win32_CeeInject_ACC_bit{
	meta:
		description = "VirTool:Win32/CeeInject.ACC!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {33 d2 b9 04 00 00 00 f7 f1 8b 45 ?? 0f be 0c 10 8b 55 ?? 0f b6 82 ?? ?? ?? ?? 33 c1 8b 4d ?? 88 81 } //1
		$a_03_1 = {8b 45 08 0f b6 08 89 4d ?? 8b 55 ?? 89 55 ?? 8b 45 08 83 c0 01 89 45 08 83 7d ?? 00 74 11 8b 4d ?? c1 e1 05 03 4d ?? 03 4d ?? 89 4d } //1
		$a_03_2 = {3b 45 0c 75 15 8b 55 ?? 8b 45 ?? 0f b7 0c 50 8b 55 ?? 8b 45 08 03 04 8a eb 04 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}