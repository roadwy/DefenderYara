
rule Worm_Win32_Taterf_DM{
	meta:
		description = "Worm:Win32/Taterf.DM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {ff d6 83 7d fc 00 0f 84 90 01 04 81 7b 90 01 01 90 90 90 90 90 90 90 90 75 90 01 01 cc 90 00 } //01 00 
		$a_03_1 = {ff d6 83 7d fc 00 74 90 01 01 80 bd 90 01 04 b8 74 90 00 } //02 00 
		$a_03_2 = {51 6a 0b ff d0 8b 45 fc 85 c0 75 90 01 01 cc e9 90 01 04 69 c0 1c 01 00 00 90 00 } //02 00 
		$a_03_3 = {83 c0 b0 51 8d 8d 90 01 04 68 00 01 00 00 51 50 ff 15 90 01 04 50 ff 15 90 01 04 85 c0 74 90 01 01 80 bd 90 01 04 b8 90 00 } //02 00 
		$a_03_4 = {ff d6 bf ff ff 00 00 23 c7 3d 16 1c 00 00 76 90 01 01 3d 20 1c 00 00 73 90 01 01 ff 75 14 ff 75 10 ff 75 0c ff 75 0c e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}