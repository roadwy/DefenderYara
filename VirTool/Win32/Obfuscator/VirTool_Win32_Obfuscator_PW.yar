
rule VirTool_Win32_Obfuscator_PW{
	meta:
		description = "VirTool:Win32/Obfuscator.PW,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_13_0 = {55 08 83 ba 90 01 02 00 00 00 74 90 14 8b 55 fc 5f 5e 59 5d 81 c4 90 01 02 00 00 ff e2 90 00 01 } //1
		$a_89_1 = {fc 83 7d fc 05 75 90 01 01 68 90 01 04 68 00 10 00 00 68 } //16384
	condition:
		((#a_13_0  & 1)*1+(#a_89_1  & 1)*16384) >=2
 
}