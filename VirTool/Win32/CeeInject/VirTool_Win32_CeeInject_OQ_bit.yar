
rule VirTool_Win32_CeeInject_OQ_bit{
	meta:
		description = "VirTool:Win32/CeeInject.OQ!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {51 6e 61 6d 65 5c 75 6e 64 65 72 72 75 6e 5c 43 68 65 72 6e 62 79 6c } //01 00 
		$a_01_1 = {8b 95 70 df ff ff 8b 85 4c df ff ff 33 85 5c df ff ff 88 02 } //01 00 
		$a_01_2 = {8b 95 fc fd ff ff 8d 43 08 89 42 01 } //00 00 
	condition:
		any of ($a_*)
 
}