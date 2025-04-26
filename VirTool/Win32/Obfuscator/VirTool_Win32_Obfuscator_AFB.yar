
rule VirTool_Win32_Obfuscator_AFB{
	meta:
		description = "VirTool:Win32/Obfuscator.AFB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {68 60 61 51 00 58 b9 ?? ?? ?? ?? ba ?? ?? ?? ?? c7 80 00 12 00 00 ?? ?? ?? ?? 03 88 00 12 00 00 c7 80 04 12 00 00 ?? ?? ?? ?? 2b } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}