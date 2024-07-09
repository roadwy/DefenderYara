
rule VirTool_Win32_Obfuscator_ET{
	meta:
		description = "VirTool:Win32/Obfuscator.ET,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 03 00 05 00 00 "
		
	strings :
		$a_07_0 = {ad 33 c2 ab 83 (c6 90 04 01 04 fd fe ff 00|ee 90 04 01 04 00 01 02 03) [0-18] c1 90 17 07 02 02 02 02 02 02 02 c2 03 c2 05 c2 0d ca 07 ca 0b ca 0d cb 0d } //3
		$a_07_1 = {ad 33 c3 ab 83 (c6 90 04 01 04 fd fe ff 00|ee 90 04 01 04 00 01 02 03) [0-18] c1 90 17 07 02 02 02 02 02 02 02 c2 03 c2 05 c2 0d ca 07 ca 0b ca 0d cb 0d } //3
		$a_03_2 = {83 f8 09 0f 84 ?? 00 00 00 90 09 04 00 03 (c6|c7) 03 90 17 03 01 01 01 c3 c6 c7 } //2
		$a_01_3 = {8b 45 fc 0f b7 0a 69 c0 3f 00 01 00 03 c1 } //1
		$a_03_4 = {94 c8 37 09 90 09 01 00 [b8-bf] } //1
	condition:
		((#a_07_0  & 1)*3+(#a_07_1  & 1)*3+(#a_03_2  & 1)*2+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=3
 
}