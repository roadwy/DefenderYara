
rule VirTool_Win32_Obfuscator_AEC{
	meta:
		description = "VirTool:Win32/Obfuscator.AEC,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 01 00 01 00 00 "
		
	strings :
		$a_0a_0 = {55 8b ec 50 b8 07 00 00 00 81 c4 04 f0 ff ff 50 48 75 f6 8b 45 fc 81 c4 ?? f2 ff ff 53 56 57 8d } //1
	condition:
		((#a_0a_0  & 1)*1) >=1
 
}