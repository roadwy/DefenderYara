
rule VirTool_Win32_CeeInject_PB_bit{
	meta:
		description = "VirTool:Win32/CeeInject.PB!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 55 fc 8a 98 90 01 04 03 d0 30 1a 40 3b c6 7c ee 90 00 } //1
		$a_03_1 = {33 d2 8b c1 5b f7 f3 85 d2 75 12 8b 45 90 01 01 2b c1 bb 90 01 04 f7 f3 30 91 90 01 04 41 3b ce 72 dc 90 00 } //1
		$a_03_2 = {8b c8 8b c2 33 d2 f7 f1 8a 82 90 01 04 30 03 ff 45 90 01 01 39 75 90 01 01 72 d5 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}