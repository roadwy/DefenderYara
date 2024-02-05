
rule VirTool_Win32_Obfuscator_ABG{
	meta:
		description = "VirTool:Win32/Obfuscator.ABG,SIGNATURE_TYPE_PEHSTR_EXT,05 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 61 63 65 74 2e 74 64 69 00 } //01 00 
		$a_01_1 = {81 7d e0 13 01 00 00 75 17 68 48 91 00 00 } //01 00 
		$a_01_2 = {03 76 3c 8b 46 34 6a 40 68 00 30 00 00 ff 76 50 } //01 00 
		$a_03_3 = {8b 46 28 03 85 90 01 02 ff ff ff d0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}