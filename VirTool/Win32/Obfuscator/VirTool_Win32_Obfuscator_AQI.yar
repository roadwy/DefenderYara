
rule VirTool_Win32_Obfuscator_AQI{
	meta:
		description = "VirTool:Win32/Obfuscator.AQI,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 08 03 45 fc 0f be 08 8b 55 10 03 55 f8 0f be 02 33 c1 8b 4d 10 03 4d f8 88 01 } //1
		$a_03_1 = {da e9 df e0 f6 c4 44 90 09 32 00 d9 05 90 01 03 00 dc 0d 90 01 03 00 d9 05 90 01 03 00 dc 0d 90 01 03 00 d8 0d 90 01 03 00 dc 0d 90 01 03 00 dc 0d 90 01 03 00 de c1 dd 05 90 01 03 00 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}