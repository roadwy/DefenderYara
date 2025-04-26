
rule VirTool_Win32_Obfuscator_AGU{
	meta:
		description = "VirTool:Win32/Obfuscator.AGU,SIGNATURE_TYPE_PEHSTR_EXT,32 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {81 2c 24 43 fe 7d 12 8d ?? ?? ?? ?? ?? ?? 81 2c 24 93 21 de 65 8d [0-40] ad 56 e3 8d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}