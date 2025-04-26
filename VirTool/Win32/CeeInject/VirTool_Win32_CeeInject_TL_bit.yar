
rule VirTool_Win32_CeeInject_TL_bit{
	meta:
		description = "VirTool:Win32/CeeInject.TL!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {85 d2 75 09 8b 45 ?? 83 c0 03 89 45 ?? 8b 4d ?? 03 4d ?? 8b 55 ?? 8a 82 ?? ?? ?? 00 88 01 eb b6 } //1
		$a_03_1 = {00 00 73 13 8b 55 ?? 03 55 ?? 8b 45 ?? 8a 88 ?? ?? ?? 00 88 0a eb db } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule VirTool_Win32_CeeInject_TL_bit_2{
	meta:
		description = "VirTool:Win32/CeeInject.TL!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b c7 33 d2 52 50 8b c1 99 03 04 24 13 54 24 04 } //1
		$a_03_1 = {8a 00 50 8b c6 33 d2 52 50 8b c1 99 03 04 24 13 54 24 04 71 ?? e8 ?? ?? ?? ?? 83 c4 08 5a 88 10 } //1
		$a_03_2 = {8b c3 33 d2 52 50 8b 06 99 03 04 24 13 54 24 04 71 05 e8 ?? ?? ?? ?? 83 c4 08 32 0d ?? ?? ?? ?? 88 08 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}