
rule VirTool_Win32_CeeInject_gen_JA{
	meta:
		description = "VirTool:Win32/CeeInject.gen!JA,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f a2 0f 31 89 d6 50 90 85 c0 0f a2 0f 31 5f 29 f8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}