
rule VirTool_Win32_Obfuscator_SI{
	meta:
		description = "VirTool:Win32/Obfuscator.SI,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 52 6c 85 37 e9 } //01 00 
		$a_01_1 = {68 a0 64 18 09 e9 } //01 00 
		$a_01_2 = {3d 49 15 8b 24 e9 } //01 00 
		$a_01_3 = {3d 90 f7 a7 53 e9 } //01 00 
		$a_01_4 = {68 c6 bd 23 00 e9 } //00 00 
	condition:
		any of ($a_*)
 
}