
rule VirTool_Win32_VBInject_gen_ES{
	meta:
		description = "VirTool:Win32/VBInject.gen!ES,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {4d 5a 52 45 e9 db 10 00 00 00 } //1
		$a_03_1 = {f3 00 01 c1 e7 04 90 01 01 ff 9d fb 12 fc 0d 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}