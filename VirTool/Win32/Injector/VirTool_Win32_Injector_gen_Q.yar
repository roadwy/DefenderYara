
rule VirTool_Win32_Injector_gen_Q{
	meta:
		description = "VirTool:Win32/Injector.gen!Q,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 1c 11 88 19 41 ff 4d 0c 75 f5 5b 03 c7 c6 00 e9 40 2b f0 8d 4c 3e fc 89 08 } //1
		$a_01_1 = {8d 85 f8 fb ff ff b9 00 01 00 00 89 10 42 83 c0 04 3b d1 7c f6 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}