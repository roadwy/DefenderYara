
rule VirTool_Win32_Obfuscator_IH{
	meta:
		description = "VirTool:Win32/Obfuscator.IH,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {31 d2 47 66 8b 17 31 f6 81 c8 ?? ?? ?? ?? 83 e8 ?? 81 e8 ?? ?? ?? ?? 0b b5 a8 fd ff ff 46 85 f6 74 1c 31 c0 23 85 c8 fe ff ff 2b 85 e0 fe ff ff 46 31 c6 29 f0 2b 85 a4 fe ff ff 21 45 90 90 09 c6 81 ea ?? ?? ?? ?? 75 b8 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}