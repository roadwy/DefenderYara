
rule VirTool_Win32_CeeInject_GC{
	meta:
		description = "VirTool:Win32/CeeInject.GC,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {0f a2 0f a2 0f 31 } //1
		$a_01_1 = {0f 31 0f 31 0f a2 } //1
		$a_03_2 = {0f a2 0f a2 e9 ?? ?? ff ff } //1
		$a_03_3 = {0f 31 0f 31 e9 ?? ?? 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=2
 
}