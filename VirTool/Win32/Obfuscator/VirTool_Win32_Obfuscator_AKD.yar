
rule VirTool_Win32_Obfuscator_AKD{
	meta:
		description = "VirTool:Win32/Obfuscator.AKD,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {f8 ff 36 58 8d 76 04 89 c2 bb 01 00 00 00 83 7d fc 00 74 05 8b 5d fc eb 01 } //01 00 
		$a_01_1 = {ac 3c c2 75 fb ac 3c 14 75 02 } //00 00 
	condition:
		any of ($a_*)
 
}