
rule VirTool_Win32_CeeInject_KXB_bit{
	meta:
		description = "VirTool:Win32/CeeInject.KXB!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a c8 80 e1 fc c0 e1 ?? 08 0f 8b 4c 24 04 d2 e0 5d 24 c0 08 06 59 c3 } //1
		$a_03_1 = {89 0c 24 c1 24 24 ?? 8b 44 24 0c 01 04 24 89 4c 24 04 c1 6c 24 04 ?? 8b 44 24 14 01 44 24 04 03 4c 24 10 89 4c 24 10 8b 44 24 10 31 04 24 8b 44 24 04 31 04 24 8b 04 24 83 c4 08 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}