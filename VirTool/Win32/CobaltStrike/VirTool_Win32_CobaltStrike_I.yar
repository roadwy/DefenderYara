
rule VirTool_Win32_CobaltStrike_I{
	meta:
		description = "VirTool:Win32/CobaltStrike.I,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 04 3e 8b 5c 3e 04 50 e8 90 01 04 53 89 45 f8 e8 90 01 04 8d 5c 30 08 3b 5d 08 77 23 8b d0 8b 45 f8 8d 4c 3e 08 e8 90 01 04 8b f3 3b 75 08 72 cc 90 00 } //01 00 
		$a_03_1 = {73 79 73 77 6f 77 36 34 90 02 08 2c 90 02 08 25 73 20 28 61 64 6d 69 6e 29 90 02 08 48 54 54 50 2f 31 2e 31 20 32 30 30 20 4f 4b 90 00 } //01 00 
		$a_01_2 = {44 09 30 09 25 30 32 64 2f 25 30 32 64 2f 25 30 32 64 20 25 30 32 64 3a 25 30 32 64 3a 25 30 32 64 09 25 73 } //00 00 
	condition:
		any of ($a_*)
 
}