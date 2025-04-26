
rule VirTool_Win32_CeeInject_MD_bit{
	meta:
		description = "VirTool:Win32/CeeInject.MD!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 55 ac 83 c2 01 89 55 ac 81 7d ac 20 8b 00 00 7d ?? eb } //1
		$a_01_1 = {8b 45 c4 03 45 ac 8b 4d fc 03 4d ac 8a 11 88 10 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule VirTool_Win32_CeeInject_MD_bit_2{
	meta:
		description = "VirTool:Win32/CeeInject.MD!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {50 51 52 e8 ?? ?? ?? ff 8b 54 ?? ?? a3 ?? ?? ?? 10 8b 44 ?? ?? 83 c4 14 8a 0c 30 32 cb 88 0c 16 46 83 fe 5e 0f 8c ?? ?? ?? ff } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule VirTool_Win32_CeeInject_MD_bit_3{
	meta:
		description = "VirTool:Win32/CeeInject.MD!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {69 d2 fd 43 03 00 81 c2 ?? ?? ?? ?? 8b c2 c1 e8 10 32 04 0b 46 88 01 8b 7d ?? 41 3b f7 7c } //1
		$a_03_1 = {51 6a 40 57 50 6a 00 ff 15 ?? ?? ?? ?? ff 55 f4 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}