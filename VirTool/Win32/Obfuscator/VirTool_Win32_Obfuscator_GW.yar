
rule VirTool_Win32_Obfuscator_GW{
	meta:
		description = "VirTool:Win32/Obfuscator.GW,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 81 38 4d 5a 74 07 2d 00 00 01 00 eb f2 40 81 38 ff 75 18 8d 75 f7 81 78 04 45 10 ff 75 75 ee 48 80 38 55 } //00 00 
	condition:
		any of ($a_*)
 
}