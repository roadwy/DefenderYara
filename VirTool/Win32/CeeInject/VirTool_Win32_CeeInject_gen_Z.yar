
rule VirTool_Win32_CeeInject_gen_Z{
	meta:
		description = "VirTool:Win32/CeeInject.gen!Z,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {81 bd 70 fb ff ff 00 00 01 00 75 02 eb 14 8b 90 01 01 38 fc ff ff 03 90 01 01 6c fb ff ff 89 90 01 01 38 fc ff ff eb bd 90 00 } //01 00 
		$a_03_1 = {be e8 03 00 00 f7 f6 2b ca 89 4d fc 83 7d 90 01 01 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}