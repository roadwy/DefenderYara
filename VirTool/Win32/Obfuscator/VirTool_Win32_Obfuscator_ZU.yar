
rule VirTool_Win32_Obfuscator_ZU{
	meta:
		description = "VirTool:Win32/Obfuscator.ZU,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {77 1d 57 9e 77 0e dc 31 90 01 a4 77 72 a0 31 90 01 19 90 03 03 03 ff 12 00 6c 82 30 90 00 } //01 00 
		$a_00_1 = {6f 00 77 00 64 00 69 00 75 00 66 00 73 00 69 00 64 00 66 00 6a 00 6c 00 6b 00 73 00 61 00 64 00 6a 00 66 00 33 00 6c 00 61 00 73 00 6b 00 6a 00 6a 00 68 00 67 00 6a 00 6b 00 68 00 67 00 6b 00 6a 00 68 00 67 00 00 00 54 00 68 00 65 00 20 00 49 00 4f 00 53 00 74 00 72 00 61 00 72 00 74 00 75 00 70 00 } //00 00 
	condition:
		any of ($a_*)
 
}