
rule VirTool_Win32_Obfuscator_BZY{
	meta:
		description = "VirTool:Win32/Obfuscator.BZY,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {81 34 24 57 44 12 ac 58 05 ?? ?? ?? ?? 8b 00 48 36 ff d0 b8 ?? ?? ?? ?? d1 e0 50 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}