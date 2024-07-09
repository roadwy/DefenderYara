
rule VirTool_Win32_CeeInject_SH_bit{
	meta:
		description = "VirTool:Win32/CeeInject.SH!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {52 6a 00 56 50 6a 00 6a 00 53 a1 ?? ?? ?? ?? 8b 00 ff d0 8b f8 80 7d 08 00 74 } //1
		$a_03_1 = {89 3b 83 c3 ?? 8b d7 2b 55 ?? 0f af 55 ?? 8b 45 ?? 0f af 45 ?? 03 c3 33 c9 } //1
		$a_03_2 = {8b c3 83 c0 ?? 8b d7 0f af 55 ?? 03 c2 8b 4d ?? 2b cf 8b d6 e8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}