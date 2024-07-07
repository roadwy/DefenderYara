
rule VirTool_Win32_CeeInject_gen_EJ{
	meta:
		description = "VirTool:Win32/CeeInject.gen!EJ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {51 50 8d 04 49 50 57 68 02 01 00 00 ff 56 44 68 ff 00 00 00 68 90 01 04 53 ff 56 28 90 00 } //1
		$a_03_1 = {ff 56 38 8b 15 90 01 04 8b 0d 90 01 04 8b 42 34 50 51 ff 56 40 a1 90 01 04 8b 0d 90 01 04 6a 40 68 00 30 00 00 8b 50 50 8b 40 34 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}