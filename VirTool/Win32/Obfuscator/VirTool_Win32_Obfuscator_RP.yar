
rule VirTool_Win32_Obfuscator_RP{
	meta:
		description = "VirTool:Win32/Obfuscator.RP,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_13_0 = {f8 c7 44 24 28 bb 4e 10 da 8d 85 90 01 02 40 00 ff d0 85 c0 90 00 00 } //00 5d 
	condition:
		any of ($a_*)
 
}