
rule VirTool_Win32_Obfuscator_ARF{
	meta:
		description = "VirTool:Win32/Obfuscator.ARF,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f 31 89 55 f4 89 45 f0 ff 15 ?? ?? ?? ?? 0f 31 89 55 fc 89 45 f8 8b 45 f8 2b 45 f0 c9 c3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}