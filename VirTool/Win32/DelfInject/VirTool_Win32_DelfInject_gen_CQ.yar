
rule VirTool_Win32_DelfInject_gen_CQ{
	meta:
		description = "VirTool:Win32/DelfInject.gen!CQ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 00 6a 00 6a 04 6a 00 6a 00 6a 00 a1 90 01 04 e8 90 01 04 50 6a 00 ff 15 90 01 04 c7 05 90 01 04 02 00 01 00 90 00 } //1
		$a_03_1 = {8b 40 24 e8 90 01 04 50 a1 90 01 04 8b 40 10 50 a1 90 1b 01 8b 40 0c 03 05 90 01 04 50 a1 90 01 04 50 ff 15 90 01 04 83 05 90 1b 01 28 90 03 07 03 43 3b 1d 90 01 04 7e 4b 0f 85 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}