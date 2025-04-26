
rule VirTool_Win32_CeeInject_gen_IK{
	meta:
		description = "VirTool:Win32/CeeInject.gen!IK,SIGNATURE_TYPE_PEHSTR_EXT,15 00 14 00 03 00 00 "
		
	strings :
		$a_01_0 = {52 41 54 41 54 41 54 41 23 52 40 23 33 72 32 69 33 30 72 69 32 33 30 69 66 30 69 33 30 32 69 30 33 32 66 6b 77 30 66 6b 52 54 00 } //1
		$a_01_1 = {77 44 62 6e 6b 6b 40 6b 60 74 73 71 68 55 00 00 57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 00 } //10
		$a_01_2 = {8a 84 14 e4 03 00 00 fe c0 88 01 41 83 ea 01 79 ef 83 ef 01 8b 0e 8b 56 04 } //10
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10) >=20
 
}