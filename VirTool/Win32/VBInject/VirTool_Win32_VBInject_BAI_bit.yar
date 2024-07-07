
rule VirTool_Win32_VBInject_BAI_bit{
	meta:
		description = "VirTool:Win32/VBInject.BAI!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 36 5f 12 00 90 02 30 05 20 a1 2f 00 90 02 30 39 01 90 02 30 0f 90 02 30 83 e9 04 90 02 30 68 73 0d 34 00 90 02 30 58 90 02 30 05 da f2 1e 00 90 02 30 8b 09 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}