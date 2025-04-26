
rule VirTool_Win32_CeeInject_UB_bit{
	meta:
		description = "VirTool:Win32/CeeInject.UB!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8d 45 f8 50 6a 40 68 ?? ?? ?? ?? 8b 45 08 50 ff 15 } //1
		$a_03_1 = {33 c0 89 45 ?? 8b 45 ?? 03 45 ?? 8a 00 88 45 [0-10] 8b 45 ?? 89 45 [0-10] 80 75 [0-10] 8b 45 ?? 03 45 ?? 8a 55 ?? 88 10 } //1
		$a_01_2 = {8b 45 08 05 df 1e 00 00 89 45 fc } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}