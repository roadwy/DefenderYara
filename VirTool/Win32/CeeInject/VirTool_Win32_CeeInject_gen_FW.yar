
rule VirTool_Win32_CeeInject_gen_FW{
	meta:
		description = "VirTool:Win32/CeeInject.gen!FW,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {cf 54 ad 05 e9 } //01 00 
		$a_01_1 = {35 24 7c 7d 32 e9 } //01 00 
	condition:
		any of ($a_*)
 
}