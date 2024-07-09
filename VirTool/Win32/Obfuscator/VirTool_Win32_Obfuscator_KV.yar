
rule VirTool_Win32_Obfuscator_KV{
	meta:
		description = "VirTool:Win32/Obfuscator.KV,SIGNATURE_TYPE_PEHSTR_EXT,64 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 04 6a 02 ?? ff 15 ?? ?? ?? ?? 83 c4 10 8b 45 f0 2d ?? ?? ?? ?? 89 45 f0 85 c0 0f 85 ?? ?? ff ff ff 15 ?? ?? ?? ?? 83 f8 7e 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}