
rule VirTool_Win32_CeeInject_gen_Z{
	meta:
		description = "VirTool:Win32/CeeInject.gen!Z,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {81 bd 70 fb ff ff 00 00 01 00 75 02 eb 14 8b ?? 38 fc ff ff 03 ?? 6c fb ff ff 89 ?? 38 fc ff ff eb bd } //1
		$a_03_1 = {be e8 03 00 00 f7 f6 2b ca 89 4d fc 83 7d ?? 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}