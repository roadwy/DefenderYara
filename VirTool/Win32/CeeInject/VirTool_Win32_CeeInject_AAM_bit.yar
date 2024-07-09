
rule VirTool_Win32_CeeInject_AAM_bit{
	meta:
		description = "VirTool:Win32/CeeInject.AAM!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b c3 bf 0a 00 00 00 99 f7 ff 80 c2 30 33 c0 8a c1 88 14 06 8b c3 bb 0a 00 00 00 99 f7 fb 8b d8 49 85 db 75 db } //1
		$a_01_1 = {89 c6 89 d7 89 c8 39 f7 77 13 74 2f c1 f9 02 78 2a f3 a5 89 c1 83 e1 03 f3 a4 } //1
		$a_03_2 = {53 31 db 69 93 ?? ?? ?? ?? ?? ?? ?? ?? 42 89 93 ?? ?? ?? ?? f7 e2 89 d0 5b } //1
		$a_03_3 = {8b d0 03 d7 89 d6 85 d2 75 05 e8 ?? ?? ?? ?? 6a 00 6a 01 57 ff d6 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}