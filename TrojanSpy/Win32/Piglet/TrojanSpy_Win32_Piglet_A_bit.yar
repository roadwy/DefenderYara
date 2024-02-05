
rule TrojanSpy_Win32_Piglet_A_bit{
	meta:
		description = "TrojanSpy:Win32/Piglet.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 8b 15 18 00 00 00 8b 52 30 8b 52 08 3b 55 0c 74 11 8b 75 10 89 f7 8b 4d 14 ad 2b 45 0c 01 d0 ab e2 f7 } //01 00 
		$a_03_1 = {74 76 5f 77 c7 45 90 01 01 33 32 2e 64 66 c7 45 90 01 01 6c 6c c6 45 f3 00 c7 45 f4 75 63 35 38 c7 45 f8 67 74 6b 2e 66 c7 45 fc 63 66 c6 45 fe 67 c6 45 ff 00 90 00 } //01 00 
		$a_01_2 = {fe c3 8a 14 1f 00 d0 8a 0c 07 88 0c 1f 88 14 07 00 d1 8a 0c 0f 30 0e 46 ff 4d 10 75 e3 } //00 00 
	condition:
		any of ($a_*)
 
}