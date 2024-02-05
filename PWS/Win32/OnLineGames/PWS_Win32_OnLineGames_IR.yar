
rule PWS_Win32_OnLineGames_IR{
	meta:
		description = "PWS:Win32/OnLineGames.IR,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {74 68 65 62 69 67 67 61 79 } //01 00 
		$a_00_1 = {4f 48 4f 48 57 45 57 45 41 52 45 30 2e } //01 00 
		$a_00_2 = {52 58 4a 48 5f 4b 49 43 4b 41 52 53 45 30 2e } //01 00 
		$a_00_3 = {44 49 41 4c 45 52 20 55 53 45 52 2e 45 58 45 } //01 00 
		$a_00_4 = {20 78 79 32 2e 65 78 65 20 2f 66 0d 0a 64 65 6c 20 25 30 } //01 00 
		$a_01_5 = {b4 f3 bb b0 ce f7 d3 ce 20 49 49 20 28 24 52 65 76 69 73 69 6f 6e 3a } //00 00 
	condition:
		any of ($a_*)
 
}