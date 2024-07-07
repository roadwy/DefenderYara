
rule VirTool_Win32_Obfuscator_AOR{
	meta:
		description = "VirTool:Win32/Obfuscator.AOR,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 c0 01 89 85 90 01 02 ff ff 81 bd 90 01 08 7d 1c 8b 8d 90 01 02 ff ff 8b 95 90 01 02 ff ff 8a 04 95 90 01 04 88 84 0d 90 01 02 ff ff 90 00 } //1
		$a_03_1 = {df e0 f6 c4 41 75 90 01 01 68 90 01 04 8d 85 90 01 02 ff ff ff e0 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}