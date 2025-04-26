
rule VirTool_Win32_Obfuscator_AXA{
	meta:
		description = "VirTool:Win32/Obfuscator.AXA,SIGNATURE_TYPE_PEHSTR_EXT,64 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 73 00 00 00 8b 0d ?? ?? ?? 00 66 89 01 ba 6f 00 00 00 a1 90 1b 00 00 66 89 50 02 b9 73 00 00 00 8b 15 90 1b 00 00 66 89 4a 18 b8 73 00 00 00 8b 0d 90 1b 00 00 66 89 41 1a ba 65 00 00 00 a1 90 1b 00 00 66 89 50 1c b9 73 00 00 00 8b 15 90 1b 00 00 66 89 4a 1e 68 ?? ?? ?? 00 a1 90 1b 00 00 50 68 02 00 00 80 ff 15 ?? ?? ?? 00 85 c0 74 07 33 c0 e9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}