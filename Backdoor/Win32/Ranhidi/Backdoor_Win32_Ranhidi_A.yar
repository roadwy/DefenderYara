
rule Backdoor_Win32_Ranhidi_A{
	meta:
		description = "Backdoor:Win32/Ranhidi.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {64 a1 30 00 00 00 8b 40 0c 8b 70 1c ad 8b 78 08 89 7d fc 8b 45 fc } //01 00 
		$a_02_1 = {6a 28 8d 4c 24 10 8b 84 24 f0 00 00 00 03 c6 50 51 e8 90 01 04 33 ff 8b 44 24 20 85 c0 76 26 8b 9c 24 74 01 00 00 8b 54 24 2c 8d 04 ba 8b 0c 30 03 ce 51 90 00 } //01 00 
		$a_00_2 = {8b 54 24 04 33 c0 8a 0a 84 c9 74 19 56 8b f0 c1 ee 1b c1 e0 05 0b f0 0f be c1 8a 4a 01 03 c6 42 84 c9 75 e9 5e } //00 00 
	condition:
		any of ($a_*)
 
}