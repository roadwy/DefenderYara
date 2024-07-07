
rule VirTool_Win32_CeeInject_AAT_bit{
	meta:
		description = "VirTool:Win32/CeeInject.AAT!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {bb 00 00 00 83 6d 90 01 01 7b 68 90 09 03 00 c7 45 90 00 } //1
		$a_03_1 = {ba 65 00 00 00 90 01 01 72 00 00 00 90 01 01 6e 00 00 00 90 00 } //1
		$a_03_2 = {8b d7 c1 ea 05 03 55 90 01 01 8b c7 c1 e0 04 03 45 90 00 } //1
		$a_01_3 = {8d 0c 33 33 d0 33 d1 2b fa } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}