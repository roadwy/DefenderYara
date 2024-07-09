
rule VirTool_Win32_VBInject_gen_EA{
	meta:
		description = "VirTool:Win32/VBInject.gen!EA,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a d8 ff 75 e4 ff 75 e0 90 09 07 00 33 ca e8 } //1
		$a_01_1 = {4c 09 09 4d 4e 4f 4a 39 4e 2f 2f 2f 50 31 37 2f 2f 2f 4e 51 0c 02 21 0b } //1 ौ䴉低㥊⽎⼯ㅐ⼷⼯兎Ȍଡ
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}