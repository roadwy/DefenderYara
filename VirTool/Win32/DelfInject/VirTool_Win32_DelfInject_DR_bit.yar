
rule VirTool_Win32_DelfInject_DR_bit{
	meta:
		description = "VirTool:Win32/DelfInject.DR!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 03 89 06 90 01 01 a1 90 01 02 48 00 03 06 8a 00 90 01 02 34 90 01 01 8b 90 01 03 48 00 03 16 88 02 90 01 01 ff 03 81 90 01 05 75 90 00 } //1
		$a_03_1 = {03 03 89 06 8b 06 89 03 ff 90 01 03 48 00 5a 90 01 01 ff e2 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}