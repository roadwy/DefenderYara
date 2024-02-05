
rule VirTool_Win32_Obfuscator_AJE{
	meta:
		description = "VirTool:Win32/Obfuscator.AJE,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 06 28 d8 aa 83 c6 01 49 83 f9 00 75 f2 8b 5c 24 04 89 d9 8b 5b 0c 89 d8 8b 5b 1c } //00 00 
	condition:
		any of ($a_*)
 
}