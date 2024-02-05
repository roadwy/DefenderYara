
rule VirTool_Win32_Obfuscator_ABA{
	meta:
		description = "VirTool:Win32/Obfuscator.ABA,SIGNATURE_TYPE_PEHSTR_EXT,05 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {66 83 21 00 ff 31 58 8b d0 6a 3c 01 04 24 90 02 06 8b 54 10 1c c1 ca 08 33 c0 90 01 03 c2 90 01 01 77 09 90 90 90 90 90 90 90 02 02 e9 90 01 01 fb ff ff 6a 00 5c fb 90 00 } //01 00 
		$a_03_1 = {58 2e ff 10 90 01 01 83 ec 90 01 01 8b 2c 24 83 c4 04 c3 90 00 } //01 00 
		$a_03_2 = {bf fc ff ff ff 2b 90 01 01 2b 90 01 01 5f 0f cf eb e0 90 02 07 68 90 01 04 58 2e ff 10 90 01 01 83 ec 90 01 01 5d c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}