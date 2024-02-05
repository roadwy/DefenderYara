
rule VirTool_Win32_Obfuscator_EP{
	meta:
		description = "VirTool:Win32/Obfuscator.EP,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {64 8b 0d 30 00 00 00 90 02 0a 8b 91 90 90 00 00 00 81 90 00 } //01 00 
		$a_01_1 = {8b 0a 39 c1 74 07 01 d9 42 31 c6 eb f3 } //00 00 
	condition:
		any of ($a_*)
 
}