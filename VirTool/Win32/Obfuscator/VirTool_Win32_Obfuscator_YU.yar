
rule VirTool_Win32_Obfuscator_YU{
	meta:
		description = "VirTool:Win32/Obfuscator.YU,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {ff 75 fc e8 90 01 04 ff 75 fc e8 90 01 04 8b 46 28 90 05 08 02 90 90 03 45 fc 90 05 08 02 90 90 ff d0 90 00 } //1
		$a_03_1 = {8b 75 08 03 76 3c 90 03 01 04 6a eb 90 14 6a 40 68 00 30 00 00 ff 76 50 ff 76 34 ff 55 f0 90 00 } //1
		$a_03_2 = {8b 75 08 03 76 3c 8b 46 34 6a 40 68 00 30 00 00 ff 76 50 50 8b 45 0c ff 90 90 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}