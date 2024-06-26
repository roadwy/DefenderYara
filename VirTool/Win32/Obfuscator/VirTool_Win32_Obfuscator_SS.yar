
rule VirTool_Win32_Obfuscator_SS{
	meta:
		description = "VirTool:Win32/Obfuscator.SS,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {b9 fa 00 00 00 c6 00 00 40 49 75 90 01 01 be 64 00 00 00 68 c8 00 00 00 90 00 } //01 00 
		$a_03_1 = {83 c1 28 8b 01 89 02 8b 41 04 89 42 04 66 8b 49 08 66 89 4a 08 8d 90 01 03 52 ff 15 90 00 } //01 00 
		$a_03_2 = {b0 4c 53 88 90 01 03 88 90 01 06 55 b3 65 8d 90 01 03 56 57 c6 90 01 03 6f c6 90 01 03 61 90 00 } //01 00 
		$a_01_3 = {6d 73 64 75 6d 70 31 35 30 61 75 72 6f 2e 74 6d 70 00 } //00 00 
	condition:
		any of ($a_*)
 
}