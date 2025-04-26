
rule VirTool_Win32_VBInject_PF_bit{
	meta:
		description = "VirTool:Win32/VBInject.PF!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {b8 30 00 00 00 [0-30] 64 ff 30 [0-30] 58 [0-30] 8b 40 0c [0-30] eb } //1
		$a_03_1 = {85 c9 0f 85 [0-30] 41 [0-30] 8b 53 2c [0-30] 31 ca [0-30] 85 d2 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}