
rule VirTool_Win32_Obfuscator_JX{
	meta:
		description = "VirTool:Win32/Obfuscator.JX,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {c7 45 cc 80 25 00 00 c6 45 d0 67 c6 45 d1 39 c6 45 d2 68 c6 45 d3 37 c6 45 d4 74 c6 45 d5 34 c6 45 d6 72 c6 45 d7 39 c6 45 d8 68 c6 45 d9 34 c6 45 da 6a c6 45 db 68 c6 45 dc 34 } //1
		$a_01_1 = {c6 85 ea fe ff ff 43 c6 85 eb fe ff ff 6c c6 85 ec fe ff ff 61 c6 85 ed fe ff ff 73 c6 85 ee fe ff ff 73 c6 85 ef fe ff ff 4f c6 85 f0 fe ff ff 62 c6 85 f1 fe ff ff 6a c6 85 f2 fe ff ff 65 c6 85 f3 fe ff ff 63 c6 85 f4 fe ff ff 74 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}