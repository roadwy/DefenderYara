
rule VirTool_Win32_VBInject_ADR_bit{
	meta:
		description = "VirTool:Win32/VBInject.ADR!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 72 a5 12 00 90 02 30 05 e4 5a 2f 00 90 02 30 39 01 90 02 30 0f 90 02 30 83 e9 04 90 02 30 68 34 8a 20 00 90 02 30 58 90 02 30 05 19 76 32 00 90 02 30 8b 09 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}