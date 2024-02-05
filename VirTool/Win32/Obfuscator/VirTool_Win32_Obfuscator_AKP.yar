
rule VirTool_Win32_Obfuscator_AKP{
	meta:
		description = "VirTool:Win32/Obfuscator.AKP,SIGNATURE_TYPE_PEHSTR_EXT,64 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {ff 16 8b c7 8b 40 3c 03 c7 8b 40 29 3d 90 01 02 00 00 0f 84 90 01 04 25 90 01 01 00 00 00 3d 90 01 01 00 00 00 0f 84 90 01 04 cc 90 00 } //01 00 
		$a_01_1 = {33 c0 8b c3 05 88 00 00 00 ff 10 85 d2 0f 85 } //00 00 
		$a_00_2 = {5d } //04 00 
	condition:
		any of ($a_*)
 
}