
rule VirTool_Win32_Obfuscator_NW{
	meta:
		description = "VirTool:Win32/Obfuscator.NW,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {80 78 02 52 75 06 80 78 01 45 74 } //1
		$a_03_1 = {8b 44 24 14 8d 90 01 02 e8 90 01 01 ff ff ff 03 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}