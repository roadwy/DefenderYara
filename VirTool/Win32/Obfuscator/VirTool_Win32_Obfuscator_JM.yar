
rule VirTool_Win32_Obfuscator_JM{
	meta:
		description = "VirTool:Win32/Obfuscator.JM,SIGNATURE_TYPE_PEHSTR_EXT,64 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {87 2c 24 c3 90 09 06 00 55 bd 90 00 } //01 00 
		$a_01_1 = {6a 00 f9 0f 82 } //00 00 
	condition:
		any of ($a_*)
 
}