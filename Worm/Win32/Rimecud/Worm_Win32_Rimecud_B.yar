
rule Worm_Win32_Rimecud_B{
	meta:
		description = "Worm:Win32/Rimecud.B,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 09 00 00 02 00 "
		
	strings :
		$a_03_0 = {74 3d e8 00 00 00 00 5e 83 c6 90 01 01 b9 90 01 04 2b e1 83 ec 90 01 01 8a 43 01 8a 90 01 01 02 f6 d0 02 90 01 01 d0 f8 8a 90 01 01 0e 02 90 01 01 32 90 01 03 88 90 01 01 0c ff e2 f1 90 00 } //02 00 
		$a_03_1 = {64 8b 0d 30 00 00 00 8b 59 68 89 9d 90 01 02 ff ff 8b 90 01 03 ff ff 83 90 01 01 70 74 07 90 00 } //02 00 
		$a_01_2 = {8b 45 f8 83 c0 01 89 45 f8 81 7d f8 fa ff ff 0f 74 02 eb ec } //02 00 
		$a_01_3 = {c6 01 2e 8b 55 10 03 55 f8 c6 42 01 65 8b 45 10 03 45 f8 c6 40 02 78 8b 4d 10 03 4d f8 c6 41 03 65 } //01 00 
		$a_00_4 = {5b 41 75 54 6f 52 75 4e 5d } //01 00  [AuToRuN]
		$a_00_5 = {50 32 50 20 43 6f 70 79 20 74 6f 3a } //01 00  P2P Copy to:
		$a_00_6 = {4d 53 4e 20 73 70 72 65 61 64 65 72 20 72 75 6e 6e 69 6e 67 } //01 00  MSN spreader running
		$a_00_7 = {55 53 42 20 73 70 72 65 61 64 65 72 20 72 75 6e 6e 69 6e 67 } //01 00  USB spreader running
		$a_00_8 = {46 6c 6f 6f 64 20 72 75 6e 6e 69 6e 67 } //00 00  Flood running
	condition:
		any of ($a_*)
 
}