
rule VirTool_Win32_CeeInject_OR_bit{
	meta:
		description = "VirTool:Win32/CeeInject.OR!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {2b f2 33 ce 03 c1 8b 0d 90 01 04 03 8d 90 01 04 88 01 90 00 } //01 00 
		$a_03_1 = {85 c9 8b 0d 90 01 04 0b fb 2b fe 87 d9 8b fb ff d7 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}