
rule VirTool_Win32_VBInject_BAL_bit{
	meta:
		description = "VirTool:Win32/VBInject.BAL!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 5e 82 12 00 [0-30] 05 f8 7d 2f 00 [0-30] 39 01 [0-30] 0f 85 4e fe ff ff [0-30] 83 e9 04 [0-30] 68 21 14 20 00 [0-30] 58 [0-30] 05 2c ec 32 00 [0-30] 8b 09 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}