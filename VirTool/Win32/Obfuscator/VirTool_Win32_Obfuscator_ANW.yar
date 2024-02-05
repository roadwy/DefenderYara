
rule VirTool_Win32_Obfuscator_ANW{
	meta:
		description = "VirTool:Win32/Obfuscator.ANW,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 db 89 d2 90 90 90 90 90 90 90 90 90 02 10 e8 90 01 03 ff 90 02 ff 5d c3 00 90 05 07 01 00 90 04 10 09 30 2d 39 41 2d 5a 61 2d 7a 90 05 30 09 30 2d 39 41 2d 5a 61 2d 7a 00 90 00 } //01 00 
		$a_03_1 = {ff 45 f4 81 7d f4 90 01 03 90 04 01 03 01 2d ff 75 90 04 01 03 d8 2d f0 90 09 20 00 90 02 20 90 90 90 90 90 02 18 ff 45 f4 81 7d 90 00 } //01 00 
	condition:
		any of ($a_*)
 
}