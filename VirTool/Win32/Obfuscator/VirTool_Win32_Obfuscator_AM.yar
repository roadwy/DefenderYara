
rule VirTool_Win32_Obfuscator_AM{
	meta:
		description = "VirTool:Win32/Obfuscator.AM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {60 61 9c 9d 50 53 51 59 5b 58 74 02 75 00 e9 00 00 00 00 68 ?? ?? ?? ?? c3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}