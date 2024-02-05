
rule VirTool_Win32_Obfuscator_BZE{
	meta:
		description = "VirTool:Win32/Obfuscator.BZE,SIGNATURE_TYPE_PEHSTR_EXT,64 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {74 1b 33 c9 8d 81 90 01 04 8a 10 80 f2 90 01 01 80 ea 90 01 01 41 88 10 81 f9 00 2c 00 00 72 90 09 07 00 80 3d 90 01 04 4d 90 00 } //01 00 
		$a_03_1 = {b9 4d 5a 00 00 dc 25 90 01 04 d9 1d 90 01 04 66 39 08 75 dd 53 8b 58 3c 03 d8 81 3b 50 45 00 00 90 00 } //00 00 
		$a_00_2 = {5d } //04 00 
	condition:
		any of ($a_*)
 
}