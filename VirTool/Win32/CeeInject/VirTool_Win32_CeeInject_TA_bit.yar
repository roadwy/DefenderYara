
rule VirTool_Win32_CeeInject_TA_bit{
	meta:
		description = "VirTool:Win32/CeeInject.TA!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {85 d2 74 7f 52 ac 30 07 47 5a 4a e2 f3 5b 5e 33 c0 c3 } //1
		$a_03_1 = {b8 c1 00 00 00 89 44 24 04 b9 ?? ?? ?? ?? 89 4c 24 08 b8 14 00 00 00 89 44 24 0c 8d 15 ?? ?? ?? ?? 89 14 24 e8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}