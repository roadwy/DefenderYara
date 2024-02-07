
rule VirTool_Win32_Obfuscator_ARJ{
	meta:
		description = "VirTool:Win32/Obfuscator.ARJ,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {03 42 28 89 45 90 01 01 6a 00 6a 01 8b 4d 90 01 01 51 ff 55 90 01 01 68 00 80 00 00 90 00 } //01 00 
		$a_03_1 = {85 c0 75 05 e9 90 01 04 8d 45 90 01 01 50 68 01 00 80 00 8b 4d 90 01 01 51 68 0e 66 00 00 90 00 } //00 00 
		$a_00_2 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}