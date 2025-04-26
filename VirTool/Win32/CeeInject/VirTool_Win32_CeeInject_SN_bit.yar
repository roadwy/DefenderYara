
rule VirTool_Win32_CeeInject_SN_bit{
	meta:
		description = "VirTool:Win32/CeeInject.SN!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b 45 08 8a 08 32 4d ec 8b 55 08 88 0a 8b 45 08 8a 08 02 4d ec 8b 55 08 88 0a } //1
		$a_03_1 = {8b 45 10 25 ?? ?? ?? ?? 99 b9 ?? ?? ?? ?? f7 f9 81 c2 } //1
		$a_01_2 = {8a c1 3c 61 7c 06 3c 7a 7f 02 24 } //1
		$a_03_3 = {8b 4d f8 8b 51 24 81 e2 ?? ?? ?? ?? f7 da 1b d2 f7 da 89 55 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}