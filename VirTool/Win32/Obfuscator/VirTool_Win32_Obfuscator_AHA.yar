
rule VirTool_Win32_Obfuscator_AHA{
	meta:
		description = "VirTool:Win32/Obfuscator.AHA,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {20 bb 0f 00 00 61 d1 9d } //01 00 
		$a_01_1 = {20 80 77 9f 5f 61 0c } //01 00 
		$a_01_2 = {20 a6 7a 00 43 61 0c } //00 00 
	condition:
		any of ($a_*)
 
}