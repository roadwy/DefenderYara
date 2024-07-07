
rule VirTool_Win32_Obfuscator_BZH{
	meta:
		description = "VirTool:Win32/Obfuscator.BZH,SIGNATURE_TYPE_PEHSTR_EXT,64 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {68 98 7f ff 79 68 90 01 03 00 e8 90 01 02 ff ff 59 59 68 98 7f ff 79 68 90 01 03 00 e8 90 01 02 ff ff 59 59 90 00 } //1
		$a_03_1 = {68 f0 3a 49 5f 68 90 01 03 00 e8 90 01 02 ff ff 59 59 68 f0 3a 49 5f 68 90 01 03 00 e8 90 01 02 ff ff 59 59 90 00 } //1
		$a_03_2 = {8b 45 0c 25 ff ff 00 00 0f b7 c0 25 ff 00 00 00 50 8b 45 08 03 45 fc 0f b6 00 50 e8 90 01 01 fe ff ff 59 59 8b 4d 08 03 4d fc 88 01 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}