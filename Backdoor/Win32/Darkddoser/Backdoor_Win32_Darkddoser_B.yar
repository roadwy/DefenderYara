
rule Backdoor_Win32_Darkddoser_B{
	meta:
		description = "Backdoor:Win32/Darkddoser.B,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 08 00 00 05 00 "
		
	strings :
		$a_03_0 = {0f b6 08 2a 0a 75 90 01 01 53 8b 58 fc 2b 5a fc 53 83 d1 ff 21 d9 2b 48 fc 29 c8 29 ca 8b 1c 01 33 1c 11 90 00 } //01 00 
		$a_01_1 = {53 54 41 54 55 53 7c 45 78 65 63 75 74 } //01 00  STATUS|Execut
		$a_01_2 = {53 54 41 54 55 53 7c 49 64 6c 65 } //01 00  STATUS|Idle
		$a_01_3 = {53 54 41 54 55 53 7c 44 6f 77 6e 6c 6f 61 64 } //01 00  STATUS|Download
		$a_01_4 = {53 54 41 54 55 53 7c 46 6c 6f 6f 64 } //01 00  STATUS|Flood
		$a_01_5 = {64 61 72 6b 64 64 6f 73 65 72 } //01 00  darkddoser
		$a_01_6 = {53 54 4f 50 46 4c 4f 4f 44 } //01 00  STOPFLOOD
		$a_03_7 = {73 76 63 68 6f 73 74 2e 65 78 65 90 02 10 44 61 52 4b 90 00 } //00 00 
		$a_00_8 = {80 10 00 00 23 32 2a } //a3 32 
	condition:
		any of ($a_*)
 
}