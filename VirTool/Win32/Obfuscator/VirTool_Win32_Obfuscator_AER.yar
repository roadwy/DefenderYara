
rule VirTool_Win32_Obfuscator_AER{
	meta:
		description = "VirTool:Win32/Obfuscator.AER,SIGNATURE_TYPE_PEHSTR_EXT,04 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 e3 00 33 c0 ?? ?? 40 00 00 c1 e0 08 b0 ?? 96 bf ?? ?? ?? ?? 03 fb [0-01] b9 00 04 00 00 f3 a5 } //1
		$a_03_1 = {83 e3 00 33 c0 ?? ?? 9c 00 00 c1 e0 08 b0 ?? 96 8d bb ?? ?? ?? ?? b9 00 04 00 00 ?? f3 a5 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}