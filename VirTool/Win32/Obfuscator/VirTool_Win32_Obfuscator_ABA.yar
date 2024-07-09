
rule VirTool_Win32_Obfuscator_ABA{
	meta:
		description = "VirTool:Win32/Obfuscator.ABA,SIGNATURE_TYPE_PEHSTR_EXT,05 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {66 83 21 00 ff 31 58 8b d0 6a 3c 01 04 24 [0-06] 8b 54 10 1c c1 ca 08 33 c0 ?? ?? ?? c2 ?? 77 09 90 90 90 90 90 90 [0-02] e9 ?? fb ff ff 6a 00 5c fb } //1
		$a_03_1 = {58 2e ff 10 ?? 83 ec ?? 8b 2c 24 83 c4 04 c3 } //1
		$a_03_2 = {bf fc ff ff ff 2b ?? 2b ?? 5f 0f cf eb e0 [0-07] 68 ?? ?? ?? ?? 58 2e ff 10 ?? 83 ec ?? 5d c3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}