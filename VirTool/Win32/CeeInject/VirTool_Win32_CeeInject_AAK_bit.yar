
rule VirTool_Win32_CeeInject_AAK_bit{
	meta:
		description = "VirTool:Win32/CeeInject.AAK!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 14 10 f7 da 8b 45 ?? 0f b6 0c 08 2b ca 8b 55 ?? 03 55 ?? 03 55 ?? 8b 45 ?? 88 0c 10 90 09 15 00 8b 4d ?? 03 4d ?? 03 4d ?? 8b 55 ?? 03 55 ?? 03 55 ?? 8b 45 } //1
		$a_03_1 = {8b ff 8b ca a3 ?? ?? ?? ?? 31 0d ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b ff c7 05 ?? ?? ?? ?? 00 00 00 00 8b ff 01 05 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}