
rule VirTool_Win32_CeeInject_BDY_bit{
	meta:
		description = "VirTool:Win32/CeeInject.BDY!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 00 50 ff 55 ec 89 45 90 8b 75 a8 8b 7d a8 8b 4d f8 } //1
		$a_01_1 = {c1 e9 02 8b 06 83 c6 04 8b 5d 90 31 d8 89 07 83 c7 04 e2 ef ff 65 a8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}