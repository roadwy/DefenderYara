
rule VirTool_Win32_CeeInject_UA_bit{
	meta:
		description = "VirTool:Win32/CeeInject.UA!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {74 35 8d 45 f8 50 6a 40 68 ?? ?? ?? ?? 8b 45 08 50 ff 15 } //1
		$a_03_1 = {8a 00 88 45 ?? 90 90 8b 45 ?? 89 45 ?? 80 75 ?? d4 8b 45 ?? 03 45 ?? 73 05 e8 ?? ?? ?? ?? 8a 55 ?? 88 10 } //1
		$a_03_2 = {8b 45 08 05 4d 36 00 00 73 05 e8 ?? ?? ?? ?? 89 45 ?? ff 65 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}