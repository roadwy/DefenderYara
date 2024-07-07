
rule VirTool_Win32_Obfuscator_XA{
	meta:
		description = "VirTool:Win32/Obfuscator.XA,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 c0 30 88 45 d8 68 40 42 0f 00 6a 00 ff 15 90 01 04 89 45 fc 0f be 4d d8 83 f1 34 83 f1 71 88 0d 90 00 } //1
		$a_03_1 = {0f b6 d0 8b 45 fc 03 45 d4 0f be 08 33 ca 8b 55 fc 03 55 d4 88 0a eb d1 90 09 17 00 8b 4d d4 83 c1 01 89 4d d4 81 7d d4 90 01 04 7d 1d e8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}