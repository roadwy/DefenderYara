
rule TrojanSpy_Win32_Seclining_gen_A{
	meta:
		description = "TrojanSpy:Win32/Seclining.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0a 00 06 00 00 05 00 "
		
	strings :
		$a_03_0 = {50 68 d9 03 00 00 68 90 01 04 8b 8d 90 01 02 ff ff 51 8b 55 dc 52 ff 15 90 01 04 85 c0 74 09 81 7d fc d9 03 00 00 74 07 90 00 } //05 00 
		$a_01_1 = {e8 00 00 00 00 5d 81 ed 05 00 00 00 b8 59 00 00 00 01 e8 50 b8 44 33 22 11 ff d0 93 b8 ed 00 00 00 } //01 00 
		$a_00_2 = {74 79 70 65 3d 70 61 73 73 77 6f 72 64 00 } //01 00  祴数瀽獡睳牯d
		$a_00_3 = {4c 6f 67 53 65 6e 64 00 } //01 00  潌卧湥d
		$a_00_4 = {47 52 42 4d 41 47 49 43 00 } //01 00 
		$a_00_5 = {64 6f 69 63 61 72 65 00 } //00 00  潤捩牡e
	condition:
		any of ($a_*)
 
}