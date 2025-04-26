
rule VirTool_Win32_CeeInject_UV_bit{
	meta:
		description = "VirTool:Win32/CeeInject.UV!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 50 ff 75 ?? ff 75 ?? ff 35 ?? ?? ?? ?? 59 ff d1 } //1
		$a_03_1 = {c6 01 00 8b 55 ?? 03 55 ?? 0f b6 02 8b 4d ?? 03 4d ?? 0f b6 11 8d 84 02 ?? ?? ?? ?? 8b 4d ?? 03 4d ?? 88 01 8b 55 ?? 03 55 ?? 0f b6 02 2d ?? ?? ?? ?? 8b 4d ?? 03 4d ?? 88 01 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}