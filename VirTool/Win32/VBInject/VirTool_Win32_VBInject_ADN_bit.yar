
rule VirTool_Win32_VBInject_ADN_bit{
	meta:
		description = "VirTool:Win32/VBInject.ADN!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 76 7e 12 00 90 02 30 05 e0 81 2f 00 90 02 30 39 01 90 02 30 0f 90 02 30 83 e9 04 90 02 30 68 27 63 20 00 90 02 30 58 90 02 30 05 26 9d 32 00 90 02 30 8b 09 90 02 30 39 c1 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}