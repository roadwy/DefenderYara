
rule VirTool_Win32_CeeInject_BDA_bit{
	meta:
		description = "VirTool:Win32/CeeInject.BDA!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {89 4c 24 04 83 44 24 04 06 8b 4c 24 0c 8a d0 d2 e2 80 e2 c0 08 55 00 } //1
		$a_01_1 = {8b 44 24 10 01 44 24 04 8b d1 03 4c 24 14 c1 e2 04 03 54 24 0c 89 4c 24 0c 89 14 24 8b 44 24 0c 31 04 24 8b 04 24 33 44 24 04 } //1
		$a_01_2 = {8b d6 c1 ea 05 03 54 24 10 8b c6 c1 e0 04 03 44 24 14 8d 0c 37 33 d0 8b 44 24 1c 33 d1 2b ea 8b 54 24 18 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}