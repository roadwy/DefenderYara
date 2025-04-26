
rule VirTool_Win32_VBInject_OV_bit{
	meta:
		description = "VirTool:Win32/VBInject.OV!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {83 f9 00 0f 85 ?? ?? ?? 00 [0-30] 8b 43 2c [0-30] 31 c8 [0-30] 83 f8 00 75 } //1
		$a_03_1 = {83 f8 00 75 [0-30] 6a 48 [0-30] 58 [0-30] 8b 14 03 [0-30] 31 f2 [0-30] 52 } //1
		$a_03_2 = {64 ff 35 18 00 00 00 [0-30] 8b ?? 30 [0-30] 02 ?? 02 [0-30] ff } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}