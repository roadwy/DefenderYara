
rule VirTool_Win32_CeeInject_BDT_bit{
	meta:
		description = "VirTool:Win32/CeeInject.BDT!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 45 f8 50 6a 40 68 90 01 04 8b 45 fc 50 e8 90 01 03 ff 90 02 10 33 c0 89 06 90 02 10 33 c0 89 45 f8 90 00 } //1
		$a_03_1 = {ff 45 f8 43 81 7d f8 90 01 04 75 b7 90 02 10 8b 4d fc 90 02 10 81 c1 90 02 10 ff d1 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}