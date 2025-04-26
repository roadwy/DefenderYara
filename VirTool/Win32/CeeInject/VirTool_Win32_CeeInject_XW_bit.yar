
rule VirTool_Win32_CeeInject_XW_bit{
	meta:
		description = "VirTool:Win32/CeeInject.XW!bit,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {8d 04 0f 99 bb ?? ?? ?? ?? f7 fb 8b 45 ?? 8a 04 02 30 01 ff 4d ?? ff 45 ?? 41 81 7d ?? 00 04 00 00 7f 05 39 75 ?? 75 d8 } //2
		$a_03_1 = {03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 45 ?? 8a 0c 02 8b 45 ?? 30 08 ff 45 ?? 8b 4d ?? 40 3b 4d ?? 89 45 ?? 7c d9 } //2
		$a_03_2 = {6a 40 03 df 8b 43 50 8b 4b 34 68 00 30 00 00 50 51 ff 75 ?? 89 4d ?? 8b 53 28 89 55 ?? ff 55 } //1
		$a_03_3 = {8d 14 39 89 10 83 c1 28 83 c0 04 3b 4d ?? 7c f0 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=5
 
}