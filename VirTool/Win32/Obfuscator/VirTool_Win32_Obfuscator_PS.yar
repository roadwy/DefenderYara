
rule VirTool_Win32_Obfuscator_PS{
	meta:
		description = "VirTool:Win32/Obfuscator.PS,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 02 00 00 "
		
	strings :
		$a_13_0 = {00 00 00 00 59 03 4d c0 83 c1 09 ff e1 52 52 52 52 52 52 52 52 52 52 8b 4d c4 90 02 0a ff 90 03 01 01 d0 d7 83 c4 08 64 a1 90 03 08 04 18 00 00 00 3e 8a 40 34 34 00 00 00 90 00 01 } //1
		$a_e8_1 = {00 00 00 59 03 4d 90 03 01 01 b8 c0 83 c1 09 ff e1 90 17 } //22016
	condition:
		((#a_13_0  & 1)*1+(#a_e8_1  & 1)*22016) >=1
 
}