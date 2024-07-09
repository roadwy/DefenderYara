
rule VirTool_Win32_CeeInject_BDV_bit{
	meta:
		description = "VirTool:Win32/CeeInject.BDV!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b ca 03 cb c6 01 ?? 43 48 75 } //1
		$a_03_1 = {05 ed 38 00 00 ff d0 90 09 05 00 a1 } //1
		$a_03_2 = {8b 07 03 c3 a3 [0-10] a1 [0-10] 8a 80 ?? ?? ?? ?? 34 ?? ?? ?? ?? 47 00 [0-10] a1 [0-10] 8a 15 f4 6b 47 00 88 10 83 05 [0-10] 02 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}