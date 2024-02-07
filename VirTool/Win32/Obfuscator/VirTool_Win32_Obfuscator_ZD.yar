
rule VirTool_Win32_Obfuscator_ZD{
	meta:
		description = "VirTool:Win32/Obfuscator.ZD,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {b9 37 13 00 00 } //01 00 
		$a_01_1 = {00 00 4d 00 79 00 20 00 46 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00 } //01 00 
		$a_01_2 = {5c 74 72 69 6f 72 61 33 5c } //01 00  \triora3\
		$a_01_3 = {79 66 69 75 6a 68 6b 00 } //00 00  晹畩桪k
	condition:
		any of ($a_*)
 
}