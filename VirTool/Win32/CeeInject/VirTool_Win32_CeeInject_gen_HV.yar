
rule VirTool_Win32_CeeInject_gen_HV{
	meta:
		description = "VirTool:Win32/CeeInject.gen!HV,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {e8 70 40 00 00 c7 44 24 04 05 2d 31 01 c7 04 24 89 46 46 47 e8 } //1
		$a_01_1 = {85 d8 30 17 85 d8 49 85 d8 47 85 d8 eb } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}