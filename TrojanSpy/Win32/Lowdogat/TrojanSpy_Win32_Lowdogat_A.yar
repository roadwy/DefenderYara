
rule TrojanSpy_Win32_Lowdogat_A{
	meta:
		description = "TrojanSpy:Win32/Lowdogat.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 6c 78 4c 6f 67 67 65 64 4f 75 74 53 41 53 } //01 00  WlxLoggedOutSAS
		$a_01_1 = {be 05 00 00 00 8a 14 01 88 10 40 4e 75 f7 } //01 00 
		$a_01_2 = {74 37 8b d6 33 c9 81 ea 1c 30 00 10 8a 84 0a 1c 30 00 10 8a 99 1c 30 00 10 3a c3 75 1c 41 83 f9 04 7c e9 } //01 00 
		$a_01_3 = {75 0b 5f 33 c0 5e 81 c4 08 01 00 00 c3 81 ff 88 13 00 00 76 0b 8d 4c 24 0c 51 ff 15 } //00 00 
	condition:
		any of ($a_*)
 
}