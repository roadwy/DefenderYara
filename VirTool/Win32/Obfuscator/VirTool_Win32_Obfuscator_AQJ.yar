
rule VirTool_Win32_Obfuscator_AQJ{
	meta:
		description = "VirTool:Win32/Obfuscator.AQJ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 81 ec 90 01 04 c6 85 90 01 05 c6 85 90 01 05 c6 85 90 01 05 c6 85 90 01 05 c6 85 90 01 05 c6 85 90 01 05 c6 85 90 01 05 c6 85 90 01 05 c6 85 90 01 05 c6 85 90 01 05 c6 85 90 01 05 c6 85 90 01 05 c6 85 90 01 05 c6 85 90 00 } //1
		$a_03_1 = {c7 45 fc 00 00 00 00 81 7d fc 40 42 0f 00 7d 17 ff 95 90 01 01 ff ff ff ff 95 90 01 01 ff ff ff 8b 4d fc 83 c1 01 89 4d fc 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}