
rule VirTool_Win32_Obfuscator_AKR{
	meta:
		description = "VirTool:Win32/Obfuscator.AKR,SIGNATURE_TYPE_PEHSTR_EXT,64 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f 31 89 85 90 01 02 ff ff 83 a5 90 01 02 ff ff 00 eb 0d 8b 85 90 01 02 ff ff 40 89 85 90 01 02 ff ff 8b 85 90 01 02 ff ff 35 90 01 04 90 03 07 01 0f 84 90 01 02 00 00 74 90 00 } //1
		$a_03_1 = {0f 31 2b 85 90 01 02 ff ff 89 85 90 01 02 ff ff 90 03 01 02 b8 c7 85 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}