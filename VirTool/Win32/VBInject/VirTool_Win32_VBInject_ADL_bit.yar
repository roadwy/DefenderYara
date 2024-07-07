
rule VirTool_Win32_VBInject_ADL_bit{
	meta:
		description = "VirTool:Win32/VBInject.ADL!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {b8 30 00 00 00 64 8b 00 8b 40 0c 8b 40 14 8b 00 8b 58 28 bf 4b 00 53 00 47 47 39 3b 75 f0 be 54 00 42 00 46 46 39 73 04 75 e4 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}