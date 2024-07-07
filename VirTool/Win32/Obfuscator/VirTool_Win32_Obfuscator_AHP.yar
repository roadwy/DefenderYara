
rule VirTool_Win32_Obfuscator_AHP{
	meta:
		description = "VirTool:Win32/Obfuscator.AHP,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {eb ce 8b 45 98 33 c9 8a 4c 05 e4 03 4d a8 89 4d 94 8b 15 90 01 04 83 c2 01 89 15 90 01 04 a1 90 01 04 03 45 c8 8a 08 02 4d 94 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}