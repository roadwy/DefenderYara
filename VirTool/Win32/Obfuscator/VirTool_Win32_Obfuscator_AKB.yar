
rule VirTool_Win32_Obfuscator_AKB{
	meta:
		description = "VirTool:Win32/Obfuscator.AKB,SIGNATURE_TYPE_PEHSTR_EXT,64 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {00 77 75 70 73 2e 64 6c 6c 00 } //01 00 
		$a_01_1 = {41 44 73 42 75 69 6c 64 45 6e 75 6d 65 72 61 74 6f 72 00 } //00 00 
	condition:
		any of ($a_*)
 
}