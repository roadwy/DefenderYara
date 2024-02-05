
rule VirTool_Win32_Obfuscator_AAP{
	meta:
		description = "VirTool:Win32/Obfuscator.AAP,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {eb 0a 8d a4 24 00 00 00 00 8d 49 00 8a 88 90 01 04 01 b0 90 01 04 02 ca 80 e9 07 83 c0 04 83 f8 76 88 0d 90 01 04 72 e1 ff 4c 24 14 75 8e 83 fb 07 74 2e 83 fb 13 74 1a 90 00 } //01 00 
		$a_03_1 = {56 8b 74 24 1c 57 8d 5c 01 f9 c7 44 24 90 01 01 60 01 00 00 eb 05 a1 90 01 04 8b 0d 90 01 04 83 f9 07 74 29 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}