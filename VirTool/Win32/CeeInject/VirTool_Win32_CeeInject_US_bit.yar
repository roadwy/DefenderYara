
rule VirTool_Win32_CeeInject_US_bit{
	meta:
		description = "VirTool:Win32/CeeInject.US!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b ca 89 45 ?? 31 4d ?? 8b 45 [0-20] 01 05 [0-10] 8b ff 8b 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 11 } //1
		$a_03_1 = {8b 55 08 8b 02 03 45 ?? 8b 4d 08 89 01 } //1
		$a_03_2 = {0f b6 08 8d 94 11 ?? ?? ?? ?? 8b 45 ?? 03 45 ?? 88 10 8b 4d ?? 03 4d ?? 0f b6 11 81 ea ?? ?? ?? ?? 8b 45 ?? 03 45 ?? 88 10 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}