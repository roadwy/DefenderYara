
rule VirTool_Win32_VBInject_BAG_bit{
	meta:
		description = "VirTool:Win32/VBInject.BAG!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 76 a1 21 00 90 02 20 05 e0 5e 20 00 90 02 20 39 01 0f 85 1d ff ff ff 90 02 20 83 e9 04 90 02 20 68 73 0d 34 00 90 02 20 58 90 02 20 05 da f2 1e 00 90 02 20 8b 09 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}