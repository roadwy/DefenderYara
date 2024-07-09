
rule VirTool_Win32_Obfuscator_IE{
	meta:
		description = "VirTool:Win32/Obfuscator.IE,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {83 ec 04 c7 04 24 40 00 00 00 68 00 30 00 00 68 ?? ?? ?? ?? 83 ec 04 c7 04 24 00 00 00 00 ff 15 ?? ?? ?? ?? 8b 0c 24 } //1
		$a_02_1 = {ff d6 55 68 00 80 00 00 6a 00 56 ff 15 ?? ?? ?? ?? 59 85 c0 0f 85 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}