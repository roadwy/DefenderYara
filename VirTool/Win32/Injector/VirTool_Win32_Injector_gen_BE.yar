
rule VirTool_Win32_Injector_gen_BE{
	meta:
		description = "VirTool:Win32/Injector.gen!BE,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {ff 71 10 8b 51 14 8b 49 0c 03 d6 03 48 34 52 51 ff 73 50 } //1
		$a_01_1 = {68 f6 3f 48 90 ff 35 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}