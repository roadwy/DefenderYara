
rule VirTool_Win32_Obfuscator_ABE{
	meta:
		description = "VirTool:Win32/Obfuscator.ABE,SIGNATURE_TYPE_PEHSTR_EXT,64 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {c6 45 c1 6c c6 45 c2 41 c6 45 c5 6f c6 45 c6 63 c6 45 bb 56 c6 45 bc 69 c6 45 c7 00 } //01 00 
		$a_01_1 = {c6 45 c8 6d c6 45 ca 78 c6 45 c9 70 8a 85 a6 fe ff ff 3a 45 c8 75 2b } //00 00 
	condition:
		any of ($a_*)
 
}