
rule VirTool_Win32_Obfuscator_AQC{
	meta:
		description = "VirTool:Win32/Obfuscator.AQC,SIGNATURE_TYPE_PEHSTR_EXT,06 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 55 d0 8b 45 d0 2d 90 01 04 89 45 ec 8b 45 d0 2d 90 01 04 89 45 e0 8b 15 90 01 04 81 c2 90 01 04 89 55 e8 8b 45 0c 81 ea 90 01 04 8b 55 d0 81 c2 90 01 04 23 c2 74 90 09 12 00 55 8b ec 83 ec 3c 8b 15 90 01 04 81 ea 90 00 } //01 00 
	condition:
		any of ($a_*)
 
}