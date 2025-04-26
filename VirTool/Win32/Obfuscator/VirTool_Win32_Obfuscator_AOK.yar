
rule VirTool_Win32_Obfuscator_AOK{
	meta:
		description = "VirTool:Win32/Obfuscator.AOK,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {56 8b 74 24 08 83 fe 08 7e ?? ff 15 ?? ?? ?? ?? 6a 2c ff 15 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 03 c1 8a 4c 24 10 03 c6 8a 10 32 d1 88 10 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}