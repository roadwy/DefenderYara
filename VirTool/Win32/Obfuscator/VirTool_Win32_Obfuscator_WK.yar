
rule VirTool_Win32_Obfuscator_WK{
	meta:
		description = "VirTool:Win32/Obfuscator.WK,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 4d f8 41 31 c0 83 e8 62 f7 d0 90 03 02 03 39 c8 83 f8 47 75 90 02 0b 32 d2 01 d8 29 c1 43 8a 53 ff 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}