
rule VirTool_Win32_Obfuscator_VG{
	meta:
		description = "VirTool:Win32/Obfuscator.VG,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {05 01 01 01 01 51 90 90 8a c8 90 90 d3 c0 90 90 59 90 90 eb 10 90 00 } //01 00 
		$a_03_1 = {e2 bb 59 8b 1d 90 01 02 00 0d ac 90 90 32 c3 90 90 aa f7 c1 01 00 00 00 74 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}