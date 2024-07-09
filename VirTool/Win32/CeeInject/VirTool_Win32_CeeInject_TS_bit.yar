
rule VirTool_Win32_CeeInject_TS_bit{
	meta:
		description = "VirTool:Win32/CeeInject.TS!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {73 24 8b 45 ?? 33 d2 f7 75 ?? 8b 45 ?? 0f b6 0c 10 8b 55 08 03 55 ?? 0f b6 02 33 c1 8b 4d 08 03 4d ?? 88 01 } //1
		$a_03_1 = {73 15 8b 4d ?? c1 e1 03 8b 55 ?? d3 ea 8b 45 ?? 03 45 ?? 88 10 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule VirTool_Win32_CeeInject_TS_bit_2{
	meta:
		description = "VirTool:Win32/CeeInject.TS!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {33 c0 89 45 ?? 99 f7 7d ?? 8b 45 ?? 8a 8a ?? ?? ?? ?? 8b 55 ?? c0 e1 03 32 c8 88 0c 02 40 3b c7 89 45 } //1
		$a_03_1 = {8b c7 99 f7 7d ?? 8b 45 ?? 8a 04 02 30 04 3e 47 3b 7d ?? 7c eb } //1
		$a_03_2 = {8b c1 99 bf ?? ?? 00 00 f7 ff 8b 45 ?? 8a 04 02 30 04 31 41 81 f9 1d 02 00 00 7c e4 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
rule VirTool_Win32_CeeInject_TS_bit_3{
	meta:
		description = "VirTool:Win32/CeeInject.TS!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 55 08 03 55 fc 0f be 1a e8 ?? ?? ?? ff 33 d8 8b 45 08 03 45 fc 88 18 eb c7 } //2
		$a_03_1 = {69 c0 fd 43 03 00 05 c3 9e 26 00 a3 ?? ?? ?? 00 a1 ?? ?? ?? 00 c1 e8 10 25 ff 7f 00 00 5d c3 } //1
		$a_03_2 = {50 6a 00 ff 15 ?? ?? ?? 00 a3 ?? ?? ?? 00 68 ?? ?? ?? 00 6a 40 8b 8d ?? ?? ff ff 51 8b 15 ?? ?? ?? 00 52 ff 15 ?? ?? ?? 00 a1 ?? ?? ?? 00 03 85 ?? ?? ff ff 8b 4d ?? 03 8d ?? ?? ff ff 8a 11 88 10 eb 91 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=4
 
}