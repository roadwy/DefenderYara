
rule VirTool_Win32_CeeInject_gen_EY{
	meta:
		description = "VirTool:Win32/CeeInject.gen!EY,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 95 9c fd ff ff 03 95 c4 fa ff ff 89 95 78 fb ff ff 8d 85 c8 fa ff ff } //01 00 
		$a_01_1 = {8b 85 6c fb ff ff 83 c0 08 } //01 00 
	condition:
		any of ($a_*)
 
}