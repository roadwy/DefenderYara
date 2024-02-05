
rule VirTool_Win32_Obfuscator_HU{
	meta:
		description = "VirTool:Win32/Obfuscator.HU,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {80 7a 78 6a 74 90 01 01 80 7a 47 89 74 90 01 01 80 7a 49 3b 74 90 01 01 cc 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}