
rule VirTool_Win32_VBInject_AIL_bit{
	meta:
		description = "VirTool:Win32/VBInject.AIL!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 76 a1 21 00 [0-30] 05 e0 5e 20 00 [0-30] 39 01 [0-30] 0f [0-30] 83 e9 04 [0-30] 68 73 0d 34 00 [0-30] 58 [0-30] 05 da f2 1e 00 [0-30] 8b 09 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}