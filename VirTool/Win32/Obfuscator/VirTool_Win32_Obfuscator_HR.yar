
rule VirTool_Win32_Obfuscator_HR{
	meta:
		description = "VirTool:Win32/Obfuscator.HR,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 61 6a 66 8b 05 90 01 04 ff d0 59 59 85 c0 0f 85 90 01 04 83 7d 0c 04 0f 83 90 01 04 0f b7 45 08 85 c0 0f 85 90 00 } //01 00 
		$a_03_1 = {6a 61 6a 66 8b 05 90 01 04 ff d0 59 59 85 c0 0f 85 90 01 04 57 ff d6 85 c0 0f 84 90 01 04 83 7d 0c 04 90 00 } //01 00 
		$a_03_2 = {6a 61 6a 66 8b 04 90 01 05 ff d0 59 59 85 c0 0f 85 90 01 04 56 8b 90 03 04 04 05 90 01 04 04 90 01 05 ff d0 85 c0 0f 84 90 01 04 83 7d 0c 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}