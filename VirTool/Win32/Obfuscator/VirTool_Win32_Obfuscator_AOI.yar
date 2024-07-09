
rule VirTool_Win32_Obfuscator_AOI{
	meta:
		description = "VirTool:Win32/Obfuscator.AOI,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 10 0f be 14 10 33 ca 90 09 07 00 99 f7 bd } //1
		$a_03_1 = {eb 0f 8b 85 ?? ?? ff ff 83 c0 01 89 85 90 1b 00 ff ff 81 bd 90 1b 00 ff ff ?? ?? ?? ?? 7d 11 8b 8d 90 1b 00 ff ff 83 c1 01 89 8d 90 1b 00 ff ff eb d4 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}