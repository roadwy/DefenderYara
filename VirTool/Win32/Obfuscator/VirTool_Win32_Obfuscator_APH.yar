
rule VirTool_Win32_Obfuscator_APH{
	meta:
		description = "VirTool:Win32/Obfuscator.APH,SIGNATURE_TYPE_PEHSTR_EXT,64 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 f8 ff 15 90 01 04 03 c7 31 45 90 01 01 8d 45 90 1b 01 50 68 90 01 04 68 04 00 00 80 ff 15 90 01 04 83 f8 06 0f 85 90 00 } //1
		$a_03_1 = {0f 31 89 55 f4 89 45 f0 ff 15 90 01 04 0f 31 89 55 fc 89 45 f8 8b 45 f8 2b 45 f0 90 00 } //2
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}