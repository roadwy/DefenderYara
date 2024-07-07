
rule VirTool_Win32_VBInject_gen_FZ{
	meta:
		description = "VirTool:Win32/VBInject.gen!FZ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 80 20 01 00 00 8b 4d 10 8b 09 8a 55 0c 88 14 08 8b 45 10 8b 00 8b 4d 08 03 81 a8 00 00 00 } //1
		$a_01_1 = {8b 48 78 f7 d9 8b 40 7c 83 d0 00 f7 d8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}