
rule VirTool_Win32_Obfuscator_N{
	meta:
		description = "VirTool:Win32/Obfuscator.N,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {60 e8 06 00 00 00 8b 64 24 08 eb 0c ?? ?? 64 ff ?? 64 89 ?? cc [0-20] 64 8f [0-10] e8 00 00 00 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}