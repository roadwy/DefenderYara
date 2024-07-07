
rule VirTool_Win32_Obfuscator_SC{
	meta:
		description = "VirTool:Win32/Obfuscator.SC,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 ec 40 8b c4 8b 4c 24 48 51 6a 00 68 00 00 10 00 50 ff 15 90 01 04 ba 90 01 04 25 ff 00 00 00 03 54 24 44 8d 48 10 83 e0 48 03 d1 89 14 04 8b 04 24 8d 4c 24 08 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}