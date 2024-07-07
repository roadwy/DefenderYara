
rule VirTool_Win32_CeeInject_UJ_bit{
	meta:
		description = "VirTool:Win32/CeeInject.UJ!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 4d fc 03 4d f8 90 01 02 8a 19 80 f3 90 01 01 88 19 90 00 } //1
		$a_03_1 = {8b 45 08 05 90 01 04 89 45 fc 90 01 02 ff 65 fc 90 00 } //1
		$a_03_2 = {50 6a 40 68 90 01 04 8b 45 fc 50 ff 55 f4 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}