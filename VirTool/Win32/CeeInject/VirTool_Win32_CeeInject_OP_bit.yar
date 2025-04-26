
rule VirTool_Win32_CeeInject_OP_bit{
	meta:
		description = "VirTool:Win32/CeeInject.OP!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {69 c9 fd 43 03 00 81 c1 c3 9e 26 00 8b d1 c1 ea 10 30 14 06 8b 55 dc 40 3b c2 7c e4 } //1
		$a_01_1 = {a1 08 ec 40 00 88 14 30 8b 55 dc 46 3b f2 72 d2 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}