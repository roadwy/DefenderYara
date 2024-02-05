
rule VirTool_Win32_Obfuscator_RM{
	meta:
		description = "VirTool:Win32/Obfuscator.RM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {ac 32 c3 aa f7 c1 01 00 00 00 74 09 60 6a 01 e8 90 01 04 61 e2 90 00 } //01 00 
		$a_03_1 = {8b 46 28 03 45 fc ff d0 68 00 80 00 00 6a 00 ff 75 fc e8 90 01 04 61 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}