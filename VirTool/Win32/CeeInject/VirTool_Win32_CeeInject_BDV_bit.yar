
rule VirTool_Win32_CeeInject_BDV_bit{
	meta:
		description = "VirTool:Win32/CeeInject.BDV!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b ca 03 cb c6 01 90 01 01 43 48 75 90 00 } //1
		$a_03_1 = {05 ed 38 00 00 ff d0 90 09 05 00 a1 90 00 } //1
		$a_03_2 = {8b 07 03 c3 a3 90 02 10 a1 90 02 10 8a 80 90 01 04 34 90 01 04 47 00 90 02 10 a1 90 02 10 8a 15 f4 6b 47 00 88 10 83 05 90 02 10 02 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}