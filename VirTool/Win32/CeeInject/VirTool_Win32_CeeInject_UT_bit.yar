
rule VirTool_Win32_CeeInject_UT_bit{
	meta:
		description = "VirTool:Win32/CeeInject.UT!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 45 08 05 45 29 00 00 73 05 } //1
		$a_01_1 = {33 c0 89 45 fc 8b 75 08 eb 05 80 33 08 eb 07 8b 5d fc 01 f3 } //1
		$a_01_2 = {40 3d d3 57 00 00 75 e3 ff 25 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}