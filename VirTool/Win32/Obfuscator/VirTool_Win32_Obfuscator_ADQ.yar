
rule VirTool_Win32_Obfuscator_ADQ{
	meta:
		description = "VirTool:Win32/Obfuscator.ADQ,SIGNATURE_TYPE_PEHSTR_EXT,64 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 00 51 6a 00 6a 00 56 6a 00 83 f8 00 75 02 ff 15 90 01 04 8b c8 3d 00 00 10 00 36 72 90 01 01 8d 80 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}