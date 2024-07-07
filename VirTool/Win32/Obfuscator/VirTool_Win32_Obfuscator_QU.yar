
rule VirTool_Win32_Obfuscator_QU{
	meta:
		description = "VirTool:Win32/Obfuscator.QU,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 4d 0c 51 e8 90 16 55 8b ec 83 ec 10 c7 45 f8 90 02 60 8b 45 f8 03 45 fc 8b 08 03 4d 08 8b 55 f8 03 55 fc 89 0a 90 00 } //1
		$a_03_1 = {8b 4d 08 51 8b 55 fc 8b 45 f8 8d 4c 10 04 51 e8 90 16 55 8b ec 51 8b 45 08 8b 08 2b 4d 0c 8b 55 08 89 0a 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}