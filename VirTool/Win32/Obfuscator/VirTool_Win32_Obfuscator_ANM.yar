
rule VirTool_Win32_Obfuscator_ANM{
	meta:
		description = "VirTool:Win32/Obfuscator.ANM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_13_0 = {00 3a 85 90 01 04 75 90 01 06 8a 00 3a 85 90 01 04 75 90 00 01 } //00 14 
		$a_8a_1 = {8b 95 90 01 04 0f af d6 2b c2 88 85 90 01 04 eb 90 00 00 } //00 01 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_Obfuscator_ANM_2{
	meta:
		description = "VirTool:Win32/Obfuscator.ANM,SIGNATURE_TYPE_PEHSTR_EXT,64 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_13_0 = {48 75 f6 8b 45 fc 81 c4 90 01 02 ff ff 53 56 57 8d bd 90 01 02 ff ff eb 90 00 01 } //00 19 
		$a_33_1 = {8a 03 8b 95 d4 b1 ff ff 8d 14 92 0f af d6 2b c2 88 } //85 da 
		$a_ff_2 = {eb 00 00 01 00 78 54 00 00 64 00 02 00 03 00 00 01 00 10 03 8a 00 3a 07 75 90 01 06 8a 00 3a 47 01 75 90 00 01 00 19 11 8a 09 8a 07 3a c8 75 c0 3a 47 01 74 bb 8b 4d fc 03 ce 8a 09 3a 4f 01 75 af 01 00 14 03 8a 03 8b 95 90 01 04 0f af d6 2b c2 88 85 90 01 04 eb 90 00 00 00 01 00 78 88 00 00 64 00 02 00 04 00 00 01 00 1b 13 50 48 75 f6 8b 45 fc 81 c4 90 01 02 ff ff 53 56 57 8d bd 90 01 02 ff ff eb 90 00 01 00 24 13 8a 12 3a 17 75 90 01 01 8b 55 fc 03 d6 8a 12 3a 57 01 75 90 01 01 8b 55 fc 03 d6 42 8a 12 3a 57 02 75 90 00 01 00 } //10 13 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_Obfuscator_ANM_3{
	meta:
		description = "VirTool:Win32/Obfuscator.ANM,SIGNATURE_TYPE_PEHSTR_EXT,64 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 00 3a 07 75 90 01 06 8a 00 3a 47 01 75 90 00 } //01 00 
		$a_11_1 = {09 8a 07 3a c8 75 c0 3a 47 01 74 bb 8b 4d fc 03 ce 8a 09 3a 4f 01 75 af 01 } //00 14 
		$a_8a_2 = {8b 95 90 } //01 04 
		$a_af_3 = {2b c2 88 85 90 01 04 eb 90 00 00 00 01 00 78 } //88 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_Obfuscator_ANM_4{
	meta:
		description = "VirTool:Win32/Obfuscator.ANM,SIGNATURE_TYPE_PEHSTR_EXT,64 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_13_0 = {48 75 f6 8b 45 fc 81 c4 90 01 02 ff ff 53 56 57 8d bd 90 01 02 ff ff eb 90 00 01 } //00 24 
		$a_8a_1 = {3a 17 75 90 01 01 8b 55 fc 03 d6 8a 12 3a 57 01 75 90 01 } //01 8b 
		$a_fc_2 = {d6 42 8a 12 3a 57 02 75 90 00 01 00 10 13 33 c0 8a 03 2b c6 88 85 90 01 02 ff ff eb 90 00 01 00 1e 13 33 c0 8a 03 8b 95 90 01 02 ff ff 8d 14 92 0f af d6 2b c2 88 85 90 01 02 ff ff eb 41 90 00 00 00 01 00 5d 04 00 00 02 40 03 80 5c 21 00 00 03 40 03 80 00 } //00 01 
	condition:
		any of ($a_*)
 
}