
rule VirTool_Win32_VBInject_ADB_bit{
	meta:
		description = "VirTool:Win32/VBInject.ADB!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 9e 5e 32 00 [0-30] 05 b8 a1 0f 00 [0-30] 39 01 [0-30] 0f [0-30] 83 e9 04 [0-30] 68 57 7e 2f 00 [0-30] 58 [0-30] 05 f6 81 23 00 [0-30] 8b 09 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}