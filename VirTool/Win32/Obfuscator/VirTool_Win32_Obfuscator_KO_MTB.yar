
rule VirTool_Win32_Obfuscator_KO_MTB{
	meta:
		description = "VirTool:Win32/Obfuscator.KO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {66 0b cf c0 e5 ?? 13 cc 8f 06 81 ef 04 00 00 00 d3 e9 66 1b ce 8b 0f 66 81 fe ?? ?? f5 66 85 f8 33 cb 66 f7 c3 ?? ?? e9 65 54 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}