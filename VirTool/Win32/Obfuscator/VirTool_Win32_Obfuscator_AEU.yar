
rule VirTool_Win32_Obfuscator_AEU{
	meta:
		description = "VirTool:Win32/Obfuscator.AEU,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {83 ec 24 c7 45 f8 01 00 00 00 c7 45 fc 7d df af 18 } //01 00 
		$a_01_1 = {4c 6f 6f 6b 43 72 79 70 74 } //01 00  LookCrypt
		$a_01_2 = {c6 05 40 55 01 10 03 c6 05 00 50 01 10 00 } //00 00 
	condition:
		any of ($a_*)
 
}