
rule VirTool_Win32_Obfuscator_AGP{
	meta:
		description = "VirTool:Win32/Obfuscator.AGP,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {81 c9 63 39 00 00 c1 e9 0c 03 4d 08 8b 55 d0 8b 75 08 8a 04 06 88 44 11 fd } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}