
rule VirTool_Win32_Injector_JG{
	meta:
		description = "VirTool:Win32/Injector.JG,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {c7 45 f4 75 73 65 72 66 c7 45 f8 33 32 c6 45 fa 00 ff 56 48 } //1
		$a_01_1 = {c7 45 b8 4d 4d 58 65 c7 45 bc 6e 56 4d 4d } //1
		$a_01_2 = {c7 45 f4 73 62 69 65 c7 45 f8 64 6c 6c 2e c7 45 fc 64 6c 6c 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}