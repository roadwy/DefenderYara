
rule VirTool_Win32_VBInject_BAG_bit{
	meta:
		description = "VirTool:Win32/VBInject.BAG!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 76 a1 21 00 [0-20] 05 e0 5e 20 00 [0-20] 39 01 0f 85 1d ff ff ff [0-20] 83 e9 04 [0-20] 68 73 0d 34 00 [0-20] 58 [0-20] 05 da f2 1e 00 [0-20] 8b 09 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}