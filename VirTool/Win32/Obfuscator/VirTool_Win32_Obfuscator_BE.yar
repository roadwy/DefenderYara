
rule VirTool_Win32_Obfuscator_BE{
	meta:
		description = "VirTool:Win32/Obfuscator.BE,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {6c 2e 64 6c 90 01 01 90 02 0f 6e 74 64 6c 90 00 } //01 00 
		$a_03_1 = {45 6e 74 72 90 01 01 90 02 0f 74 4c 64 74 90 01 01 90 02 0f 4e 74 53 65 90 00 } //01 00 
		$a_03_2 = {51 68 00 04 00 00 68 00 00 00 00 01 90 01 37 00 74 08 90 01 02 5f 59 f3 a4 eb f2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}