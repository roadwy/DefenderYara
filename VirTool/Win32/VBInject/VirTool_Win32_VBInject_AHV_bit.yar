
rule VirTool_Win32_VBInject_AHV_bit{
	meta:
		description = "VirTool:Win32/VBInject.AHV!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {39 01 0f 85 90 02 30 59 90 02 30 8b 73 10 90 02 30 89 f7 90 02 30 8b 5e 3c 90 02 30 01 de 90 02 30 8b 5e 78 90 00 } //1
		$a_03_1 = {bb 40 00 00 00 90 02 30 53 90 02 30 ba 00 30 00 00 90 02 30 52 90 02 30 68 00 90 02 30 6a 00 90 02 30 ff d0 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}