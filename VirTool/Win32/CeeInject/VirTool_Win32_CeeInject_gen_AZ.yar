
rule VirTool_Win32_CeeInject_gen_AZ{
	meta:
		description = "VirTool:Win32/CeeInject.gen!AZ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {07 00 01 00 75 0e 8b 43 10 03 43 1c 89 85 } //1
		$a_01_1 = {75 04 c6 45 ff 01 8a 45 ff 32 c1 fe 45 ff 88 02 42 4f 75 db } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}