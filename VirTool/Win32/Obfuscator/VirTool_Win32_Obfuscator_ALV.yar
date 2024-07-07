
rule VirTool_Win32_Obfuscator_ALV{
	meta:
		description = "VirTool:Win32/Obfuscator.ALV,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {b8 01 02 10 80 f7 eb 03 d3 c1 fa 0a 8b ca c1 e9 1f 03 ca } //1
		$a_03_1 = {83 f8 16 74 02 33 c0 83 c0 01 33 d0 8b d1 83 45 90 01 01 21 83 75 90 01 01 05 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}