
rule VirTool_Win32_Obfuscator_OM{
	meta:
		description = "VirTool:Win32/Obfuscator.OM,SIGNATURE_TYPE_PEHSTR_EXT,64 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {68 01 00 00 7d 3c 8b 15 90 01 04 33 c0 8a 02 8b 0d 90 01 04 33 d2 8a 11 33 c2 8b 0d 90 01 04 88 01 8b 15 90 01 04 83 c2 01 89 15 90 01 04 a1 90 01 04 83 c0 01 a3 90 01 04 eb b8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}