
rule VirTool_Win32_CeeInject_BDU_bit{
	meta:
		description = "VirTool:Win32/CeeInject.BDU!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b da 03 d9 c6 03 90 01 01 90 02 10 41 48 75 f4 90 00 } //1
		$a_03_1 = {89 45 fc 8b 45 fc 68 90 01 04 01 04 24 c3 90 00 } //1
		$a_03_2 = {32 c2 8b 55 fc 88 02 90 02 10 8b 45 f8 89 45 fc c7 45 f8 01 00 00 00 8b 45 f8 01 45 fc 8b 45 f8 01 45 fc 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}