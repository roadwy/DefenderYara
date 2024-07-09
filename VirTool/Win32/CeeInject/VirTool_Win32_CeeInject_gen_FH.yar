
rule VirTool_Win32_CeeInject_gen_FH{
	meta:
		description = "VirTool:Win32/CeeInject.gen!FH,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 51 50 8b 4e 3c 6a 40 68 00 30 00 00 52 8b 54 31 34 } //1
		$a_03_1 = {ff ff 02 00 01 00 90 09 04 00 c7 85 } //1
		$a_01_2 = {68 d8 cb 88 56 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}