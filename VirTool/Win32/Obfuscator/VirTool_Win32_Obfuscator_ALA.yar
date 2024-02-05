
rule VirTool_Win32_Obfuscator_ALA{
	meta:
		description = "VirTool:Win32/Obfuscator.ALA,SIGNATURE_TYPE_PEHSTR_EXT,32 00 08 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {ff ff 98 7f ff 79 } //05 00 
		$a_03_1 = {25 ff ff 00 00 0f b7 c0 25 ff 00 00 00 0f b6 c0 8b 90 02 05 0f be 90 02 05 33 c8 8b 90 02 05 88 90 02 05 8b 90 02 05 d1 e8 89 90 02 05 8b 90 02 05 0f be 90 02 05 8b 90 02 05 41 89 90 02 05 85 c0 75 90 00 } //02 00 
		$a_01_2 = {f3 a9 94 9d 9c 90 cd cd 51 db b3 83 f7 00 00 00 } //00 00 
		$a_00_3 = {78 ae 00 00 32 00 } //08 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_Obfuscator_ALA_2{
	meta:
		description = "VirTool:Win32/Obfuscator.ALA,SIGNATURE_TYPE_PEHSTR_EXT,32 00 08 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {e3 cf 29 6f } //05 00 
		$a_03_1 = {25 ff ff 00 00 0f b7 c0 25 ff 00 00 00 0f b6 c0 8b 90 02 05 0f be 90 02 05 33 c8 8b 90 02 05 88 90 02 05 8b 90 02 05 d1 e8 89 90 02 05 8b 90 02 05 0f be 90 02 05 8b 90 02 05 41 89 90 02 05 85 c0 75 90 00 } //01 00 
		$a_01_2 = {88 94 8a 92 9b 13 0c ad e1 83 1f 55 9c 00 00 00 } //01 00 
		$a_01_3 = {88 08 8b 45 f0 c1 e8 10 25 ff ff 00 00 0f b7 c0 89 45 e0 8b 45 f0 25 ff ff 00 00 0f b7 c0 25 ff 00 00 00 0f b6 c0 0f af 45 e0 03 45 f0 03 45 e0 89 45 e0 8b 45 e0 05 17 54 00 00 } //00 00 
		$a_00_4 = {5d 04 00 00 d2 22 } //03 80 
	condition:
		any of ($a_*)
 
}