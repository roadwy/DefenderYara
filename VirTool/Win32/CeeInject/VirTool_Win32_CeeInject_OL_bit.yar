
rule VirTool_Win32_CeeInject_OL_bit{
	meta:
		description = "VirTool:Win32/CeeInject.OL!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 5c 24 10 33 5c 24 ?? 33 5c 24 ?? 33 5c 24 ?? 33 5c 24 ?? 03 5c 24 ?? 2b 5c 24 ?? 2b 5c 24 ?? 03 5c 24 ?? 89 5c 24 } //1
		$a_03_1 = {8b 5c 24 10 33 5c 24 ?? 33 5c 24 ?? 33 5c 24 ?? 8b 7c 24 ?? 03 7c 24 ?? 01 ff 8b 74 24 ?? 03 74 24 ?? 01 f6 29 f7 03 7c 24 ?? 31 fb 89 5c 24 } //1
		$a_03_2 = {bd 30 a0 40 00 89 2d ?? ?? 48 00 ff 35 ?? ?? 48 00 ff 35 ?? ?? 48 00 ff 15 ?? ?? 48 00 } //2
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*2) >=3
 
}