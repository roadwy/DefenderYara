
rule VirTool_Win32_CeeInject_AED_bit{
	meta:
		description = "VirTool:Win32/CeeInject.AED!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {6a 40 68 00 10 00 00 51 6a 00 ff d7 a3 90 01 03 00 eb 90 00 } //1
		$a_03_1 = {88 14 30 81 fe 77 0a 00 00 90 09 12 00 8b 0d 90 01 04 8a 94 31 90 01 03 00 a1 90 01 03 00 90 00 } //1
		$a_03_2 = {30 14 3e 46 3b f3 7c 90 09 06 00 8a 15 90 01 03 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}