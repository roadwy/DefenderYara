
rule VirTool_Win32_Obfuscator_AL{
	meta:
		description = "VirTool:Win32/Obfuscator.AL,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {eb 06 56 52 55 4c 5a 00 90 05 20 01 90 8b 04 24 83 e8 4f 68 ?? ?? ?? ?? ff d0 [0-ff] c3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}