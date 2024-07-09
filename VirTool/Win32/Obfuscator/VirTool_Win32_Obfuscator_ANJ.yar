
rule VirTool_Win32_Obfuscator_ANJ{
	meta:
		description = "VirTool:Win32/Obfuscator.ANJ,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {52 74 6c 44 c7 45 ?? 65 63 6f 6d c7 45 ?? 70 72 65 73 c7 45 ?? 73 42 75 66 66 c7 45 ?? 66 65 c6 45 ?? 72 c6 45 ?? 00 c7 45 ?? 6e 74 64 6c c7 45 ?? 6c 2e 64 6c c6 45 ?? 6c c6 45 ?? 00 60 e8 00 00 00 00 58 66 b8 00 00 66 bb 4d 5a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}