
rule VirTool_Win32_VBInject_PB_bit{
	meta:
		description = "VirTool:Win32/VBInject.PB!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {85 c9 0f 85 [0-40] 41 [0-40] ff 73 2c [0-40] 31 0c 24 } //1
		$a_03_1 = {83 fa 00 75 [0-40] 6a 78 [0-40] 58 [0-40] 31 d2 [0-40] 48 [0-40] 48 [0-40] 48 [0-40] 48 [0-40] 33 14 03 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}