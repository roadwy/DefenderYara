
rule Ransom_Win32_GandCrab_BB_bit{
	meta:
		description = "Ransom:Win32/GandCrab.BB!bit,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 02 00 "
		
	strings :
		$a_03_0 = {1f 2b 55 00 7e 2a 81 bd 90 01 04 31 46 34 00 74 1e 81 bd 90 01 04 7c 7f 00 00 74 12 81 bd 90 01 04 a9 cc 52 00 74 06 90 00 } //02 00 
		$a_01_1 = {8b 45 08 0f b6 08 0f b6 55 14 c1 e2 02 81 e2 c0 00 00 00 0b ca 8b 45 08 88 08 } //02 00 
		$a_03_2 = {83 c4 10 8b 4d 90 01 01 2b c8 89 4d 90 01 01 8b 55 90 01 01 83 c2 09 8b 45 90 01 01 2b c2 90 09 15 00 8b 45 90 01 01 50 8b 4d 90 01 01 51 8b 55 90 01 01 52 8b 45 90 01 01 50 e8 90 00 } //01 00 
		$a_03_3 = {75 6b c6 05 90 01 04 6b c6 05 90 01 04 65 c6 05 90 01 04 72 c6 05 90 01 04 6e c6 05 90 01 04 65 c6 05 90 01 04 6c c6 05 90 01 04 33 c6 05 90 01 04 32 c6 05 90 01 04 2e c6 05 90 01 04 64 c6 05 90 01 04 6c c6 05 90 01 04 6c 90 00 } //01 00 
		$a_01_4 = {8b 45 08 c1 e0 04 03 45 0c 8b 4d 08 03 4d 10 33 c1 8b 55 08 c1 ea 05 03 55 14 33 c2 } //01 00 
		$a_01_5 = {56 69 72 74 75 61 6c 50 72 6f 74 73 63 74 } //00 00  VirtualProtsct
	condition:
		any of ($a_*)
 
}