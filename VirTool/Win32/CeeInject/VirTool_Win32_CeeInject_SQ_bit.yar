
rule VirTool_Win32_CeeInject_SQ_bit{
	meta:
		description = "VirTool:Win32/CeeInject.SQ!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b c1 c1 e8 10 30 04 3a 42 3b 55 ?? 7c 90 09 0c 00 69 c9 ?? ?? ?? ?? 81 c1 } //1
		$a_03_1 = {77 3f 2b f8 b8 ?? ?? ?? ?? f7 ef c1 fa 02 8b fa c1 ef 1f 03 fa 3b 4e 08 75 } //1
		$a_03_2 = {72 3b 2b 0b b8 ?? ?? ?? ?? f7 e9 33 c9 47 c1 fa 02 8b f2 c1 ee 1f 03 f2 ba ?? ?? ?? ?? 8b c6 d1 e8 2b d0 03 c6 3b d6 0f 43 c8 3b cf 0f 43 f9 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}