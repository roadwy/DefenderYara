
rule VirTool_Win32_VBInject_PB_bit{
	meta:
		description = "VirTool:Win32/VBInject.PB!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {85 c9 0f 85 90 02 40 41 90 02 40 ff 73 2c 90 02 40 31 0c 24 90 00 } //1
		$a_03_1 = {83 fa 00 75 90 02 40 6a 78 90 02 40 58 90 02 40 31 d2 90 02 40 48 90 02 40 48 90 02 40 48 90 02 40 48 90 02 40 33 14 03 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}