
rule VirTool_Win32_Obfuscator_QC{
	meta:
		description = "VirTool:Win32/Obfuscator.QC,SIGNATURE_TYPE_PEHSTR_EXT,04 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {eb 0a 80 f1 90 01 01 80 90 03 01 01 c1 e9 90 01 01 88 08 40 42 8a 0a 84 c9 90 00 } //01 00 
		$a_03_1 = {6a 00 6a 14 8d 4d 90 01 01 51 ff d0 90 03 01 01 eb e9 90 00 } //01 00 
		$a_01_2 = {8b 4d f4 8b 11 33 d6 03 d7 3b c2 0f 82 92 } //00 00 
	condition:
		any of ($a_*)
 
}