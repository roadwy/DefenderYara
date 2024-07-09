
rule VirTool_Win32_CeeInject_gen_IE{
	meta:
		description = "VirTool:Win32/CeeInject.gen!IE,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {64 a1 30 00 00 00 8a 40 02 88 85 ?? ?? ff ff 8b 85 ?? ?? ff ff 25 ff 00 00 00 85 c0 74 11 8b f4 6a 00 ff 15 } //1
		$a_03_1 = {6a 00 6a 01 8d 45 fc 50 8b 0d ?? ?? ?? ?? 51 8b fc ff 15 ?? ?? ?? ?? 3b fc e8 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 3b f4 e8 ?? ?? ?? ?? 8b 55 fc 81 e2 ff 00 00 00 81 fa e9 00 00 00 75 04 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}