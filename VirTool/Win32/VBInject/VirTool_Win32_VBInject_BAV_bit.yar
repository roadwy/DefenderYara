
rule VirTool_Win32_VBInject_BAV_bit{
	meta:
		description = "VirTool:Win32/VBInject.BAV!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 72 a5 12 00 [0-30] 05 e4 5a 2f 00 [0-30] 39 01 [0-30] 0f [0-30] 83 e9 04 [0-30] 68 94 99 06 00 [0-30] 58 [0-30] 05 b9 66 4c 00 [0-30] 8b 09 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}