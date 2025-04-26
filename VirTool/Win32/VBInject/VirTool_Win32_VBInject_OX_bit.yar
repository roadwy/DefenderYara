
rule VirTool_Win32_VBInject_OX_bit{
	meta:
		description = "VirTool:Win32/VBInject.OX!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {85 c9 0f 85 [0-30] 41 [0-30] 8b 53 2c [0-30] 31 ca [0-30] 83 fa 00 75 } //1
		$a_03_1 = {83 fa 00 75 [0-30] 89 ce [0-30] 6a 78 [0-30] 58 [0-30] 31 d2 [0-50] 33 14 03 [0-30] e8 ?? ?? ?? 00 [0-30] 83 f8 00 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}