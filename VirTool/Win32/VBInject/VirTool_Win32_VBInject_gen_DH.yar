
rule VirTool_Win32_VBInject_gen_DH{
	meta:
		description = "VirTool:Win32/VBInject.gen!DH,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {ff 94 08 00 28 02 aa 99 08 00 50 01 } //1
		$a_03_1 = {f3 c3 00 fc 0d 90 02 30 f3 cc 00 fc 0d 90 00 } //1
		$a_03_2 = {80 0c 00 fc 90 90 fd d0 08 00 90 01 01 00 fb 11 94 08 00 90 01 01 00 80 0c 00 90 00 } //1
		$a_03_3 = {ff f5 f8 00 00 00 aa f5 28 00 00 00 6c 90 01 01 ff b2 aa f5 90 04 01 02 0c 14 00 00 00 aa 90 09 02 00 6c 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}