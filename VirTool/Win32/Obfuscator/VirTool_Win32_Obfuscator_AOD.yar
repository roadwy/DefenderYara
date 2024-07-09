
rule VirTool_Win32_Obfuscator_AOD{
	meta:
		description = "VirTool:Win32/Obfuscator.AOD,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {32 d1 80 fa f2 88 94 35 ?? ?? ff ff 77 ?? fe ca 88 94 35 ?? ?? ff ff 46 } //1
		$a_03_1 = {df e0 f6 c4 41 75 ?? 68 ?? ?? ?? ?? 6a 00 8d 8d ?? ?? ff ff ff d1 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}