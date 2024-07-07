
rule VirTool_Win32_VBInject_OX_bit{
	meta:
		description = "VirTool:Win32/VBInject.OX!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {85 c9 0f 85 90 02 30 41 90 02 30 8b 53 2c 90 02 30 31 ca 90 02 30 83 fa 00 75 90 00 } //1
		$a_03_1 = {83 fa 00 75 90 02 30 89 ce 90 02 30 6a 78 90 02 30 58 90 02 30 31 d2 90 02 50 33 14 03 90 02 30 e8 90 01 03 00 90 02 30 83 f8 00 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}