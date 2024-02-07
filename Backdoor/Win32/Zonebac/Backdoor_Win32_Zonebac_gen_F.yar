
rule Backdoor_Win32_Zonebac_gen_F{
	meta:
		description = "Backdoor:Win32/Zonebac.gen!F,SIGNATURE_TYPE_PEHSTR_EXT,07 00 06 00 08 00 00 07 00 "
		
	strings :
		$a_02_0 = {e8 ef fb ff ff 68 00 00 08 00 ff 35 90 01 02 41 00 e8 df fb ff ff 83 c4 28 5e 90 00 } //02 00 
		$a_02_1 = {76 16 8b 15 90 01 03 00 8b c8 83 e1 1f 8a 0c 11 30 0c 38 40 3b c6 72 ea 90 00 } //02 00 
		$a_02_2 = {ff 74 24 04 6b c0 44 05 90 01 03 00 50 ff 15 90 01 03 00 a1 90 01 03 00 8b 4c 24 08 6b c0 44 ff 05 90 01 03 00 89 88 90 01 03 00 c3 90 00 } //02 00 
		$a_02_3 = {ff 75 fc 6a 01 68 ff 90 01 01 1f 00 ff 15 90 01 03 00 3b c6 74 08 56 50 ff 15 90 01 03 00 57 ff 15 90 01 03 00 90 00 } //03 00 
		$a_02_4 = {50 53 ff d6 81 7d f8 90 01 02 00 00 74 3f 6a 02 57 6a f4 53 ff 15 90 00 } //03 00 
		$a_00_5 = {ff d6 81 7d f0 67 2b 00 00 5e 75 1b } //01 00 
		$a_00_6 = {68 74 74 70 3a 2f 2f 38 38 2e 38 30 2e } //01 00  http://88.80.
		$a_00_7 = {5c 61 62 63 31 32 33 2e 70 69 64 } //00 00  \abc123.pid
	condition:
		any of ($a_*)
 
}