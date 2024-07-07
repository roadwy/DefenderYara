
rule VirTool_Win32_CeeInject_AAO_bit{
	meta:
		description = "VirTool:Win32/CeeInject.AAO!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 37 6b f9 90 01 01 01 f8 33 10 89 d8 03 44 24 90 01 01 89 e7 89 57 08 89 77 04 89 07 89 54 24 90 01 01 89 4c 24 90 01 01 89 5c 24 90 01 01 e8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}