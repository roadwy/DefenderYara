
rule VirTool_Win32_Obfuscator_APG{
	meta:
		description = "VirTool:Win32/Obfuscator.APG,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 44 24 ?? 3c ?? 75 02 eb 90 0a 1c 00 ff 15 ?? ?? ?? 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}