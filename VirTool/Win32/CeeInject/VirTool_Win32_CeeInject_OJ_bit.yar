
rule VirTool_Win32_CeeInject_OJ_bit{
	meta:
		description = "VirTool:Win32/CeeInject.OJ!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {79 05 4a 83 ca ?? 42 85 d2 75 ?? 8b 45 ?? 83 c0 ?? 89 45 ?? 8b 4d ?? 03 4d ?? 8b 55 ?? 8a 82 ?? ?? ?? ?? 88 01 } //1
		$a_03_1 = {8b ec 51 8b 45 0c 89 45 fc 8b 4d 08 33 4d fc 89 4d 08 8b 55 fc 83 c2 ?? 89 55 fc 8b 45 08 2d ?? ?? ?? ?? 89 45 08 8b 4d fc 81 e9 ?? ?? ?? ?? 89 4d fc c1 4d 08 ?? 8b 45 08 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}