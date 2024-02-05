
rule VirTool_Win32_Obfuscator_HA{
	meta:
		description = "VirTool:Win32/Obfuscator.HA,SIGNATURE_TYPE_PEHSTR_EXT,09 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {c1 e8 10 83 c0 02 8d 80 90 01 04 ff e0 90 00 } //01 00 
		$a_03_1 = {64 8b 15 18 00 00 00 41 52 90 02 10 5e 48 c7 46 14 90 00 } //01 00 
		$a_01_2 = {c7 46 14 38 37 36 34 01 f0 } //02 00 
		$a_01_3 = {0f 70 ca ff 0f 77 } //00 00 
	condition:
		any of ($a_*)
 
}