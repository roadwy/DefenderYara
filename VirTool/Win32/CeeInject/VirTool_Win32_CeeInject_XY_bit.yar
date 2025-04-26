
rule VirTool_Win32_CeeInject_XY_bit{
	meta:
		description = "VirTool:Win32/CeeInject.XY!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_42_0 = {6c 33 32 c6 44 24 90 01 01 00 ff d3 a3 90 00 01 } //1
		$a_00_1 = {10 56 8b f8 ff 15 90 01 02 00 10 68 90 01 02 00 10 8b f0 ff d7 6a 00 ff d6 90 00 01 00 0f 40 8b c1 99 f7 fe 8a 04 2a 30 04 19 41 4f 75 f1 00 00 7e 15 00 00 88 73 b4 91 b9 aa 07 03 12 7b d0 4b ad c9 } //7168
	condition:
		((#a_42_0  & 1)*1+(#a_00_1  & 1)*7168) >=2
 
}