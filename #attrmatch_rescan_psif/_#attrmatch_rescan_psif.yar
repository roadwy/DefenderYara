
rule _#attrmatch_rescan_psif{
	meta:
		description = "!#attrmatch_rescan_psif,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 40 28 83 c0 0e 66 8b 00 66 3b 45 e6 0f 84 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#attrmatch_rescan_psif_2{
	meta:
		description = "!#attrmatch_rescan_psif,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 43 28 83 c0 90 01 01 66 8b 00 66 3b 45 e6 0f 84 4e 02 00 00 90 00 } //00 00 
		$a_00_1 = {78 } //3a 00  x
	condition:
		any of ($a_*)
 
}
rule _#attrmatch_rescan_psif_3{
	meta:
		description = "!#attrmatch_rescan_psif,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {0f 31 89 c3 0f 31 29 d8 77 fa } //01 00 
		$a_03_1 = {e8 00 00 00 00 58 89 45 90 01 01 c6 45 90 01 01 59 c6 45 90 01 01 2a c6 45 90 01 01 38 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#attrmatch_rescan_psif_4{
	meta:
		description = "!#attrmatch_rescan_psif,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {51 c7 45 fc 02 00 00 00 e8 90 01 04 85 c0 74 04 83 45 fc 06 8b 45 fc ff 14 85 90 00 } //01 00 
		$a_03_1 = {51 c7 45 fc 02 00 00 00 e8 90 01 04 85 c0 74 09 8b 45 fc 83 c0 06 89 45 fc 8b 4d fc ff 14 8d 90 00 } //01 00 
		$a_03_2 = {51 c7 04 24 02 00 00 00 e8 90 01 04 85 c0 74 09 8b 04 24 83 c0 06 89 04 24 8b 0c 24 ff 14 8d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#attrmatch_rescan_psif_5{
	meta:
		description = "!#attrmatch_rescan_psif,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {56 69 72 41 6c 6c 78 00 6d 79 61 70 70 2e 65 78 65 } //01 00 
		$a_01_1 = {6d 79 61 70 70 2e 65 78 65 00 00 00 71 65 6d 75 } //01 00 
		$a_01_2 = {01 46 46 46 1f 5c 5c 5c 69 68 67 68 b9 73 72 73 } //01 00 
		$a_01_3 = {6d 79 61 70 70 2e 65 78 65 00 00 00 73 52 61 53 } //01 00 
		$a_03_4 = {6d 79 61 70 70 2e 65 78 65 00 00 00 00 53 00 4f 00 46 90 01 7b 61 00 76 00 61 00 73 00 74 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#attrmatch_rescan_psif_6{
	meta:
		description = "!#attrmatch_rescan_psif,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {64 8b 1d 30 00 00 00 89 5d fc 8b 45 fc 8b 40 0c 8b 70 0c 66 c7 45 90 01 01 70 00 66 c7 45 90 01 01 6d 00 66 c7 45 90 01 01 62 00 8b 46 28 90 00 } //01 00 
		$a_03_1 = {e8 00 00 00 00 58 89 45 90 01 01 c6 45 90 01 01 59 c6 45 90 01 01 2a c6 45 90 01 01 38 33 90 03 02 02 c0 40 d2 42 8b 90 03 01 01 4d 75 90 1b 00 90 00 } //01 00 
		$a_03_2 = {66 8b 00 66 3b 85 90 01 02 ff ff 74 16 8b 45 90 01 01 8b 40 28 83 c0 06 66 8b 00 66 3b 85 90 01 02 ff ff 75 01 c3 90 00 } //01 00 
		$a_03_3 = {64 8b 15 30 00 00 00 89 55 fc 8b 45 fc 8b 40 0c 8b 48 0c 66 c7 85 90 01 02 ff ff 90 01 01 00 66 c7 85 90 01 02 ff ff 90 01 01 00 8b 41 28 90 00 } //01 00 
		$a_01_4 = {8b 5e 28 8b f8 03 ff 03 df 66 8b 1b 66 89 19 40 83 c1 02 4a 75 ea } //01 00 
		$a_03_5 = {8b 43 28 8b d0 83 c2 90 01 01 66 8b 12 66 3b 55 90 01 01 0f 84 90 01 04 83 c0 90 01 01 66 8b 00 66 3b 45 90 01 01 0f 84 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#attrmatch_rescan_psif_7{
	meta:
		description = "!#attrmatch_rescan_psif,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 07 00 00 01 00 "
		
	strings :
		$a_03_0 = {ff d7 c6 45 90 01 01 43 c6 45 90 01 01 6d c6 45 90 01 01 61 c6 45 90 01 01 2e 8a 85 90 01 02 ff ff 3a 45 90 01 01 75 90 01 01 8a 85 90 01 02 ff ff 3a 45 90 01 01 75 90 01 01 8a 85 90 01 02 ff ff 3a 45 90 01 01 75 90 01 01 8a 85 90 01 02 ff ff 3a 45 90 01 01 75 90 00 } //01 00 
		$a_03_1 = {66 8b 09 66 8b 55 90 01 01 66 3b ca 75 90 09 1d 00 66 c7 45 90 01 01 70 00 66 c7 45 90 01 01 6d 00 66 c7 45 90 01 01 62 00 8b 45 90 01 01 8b 40 90 01 01 8b c8 83 c1 0c 90 00 } //01 00 
		$a_03_2 = {64 8b 05 30 00 00 00 89 45 90 01 01 8b 45 90 01 01 8b 40 0c 8b 70 0c 66 c7 45 90 01 01 6d 00 66 c7 45 90 01 01 61 00 8b 46 28 8b d0 83 c2 06 66 8b 12 66 3b 55 90 01 01 75 90 00 } //01 00 
		$a_03_3 = {64 8b 15 30 00 00 00 89 55 90 01 01 8b 45 90 01 01 8b 40 0c 8b 48 0c 66 c7 85 90 01 02 ff ff 90 04 01 05 6d 79 61 70 70 00 66 c7 85 90 01 02 ff ff 90 04 01 05 6d 79 61 70 70 00 8b 41 28 8b d0 83 c2 90 01 01 66 8b 12 66 3b 95 90 01 02 ff ff 75 90 00 } //01 00 
		$a_03_4 = {64 8b 15 30 00 00 00 89 55 90 01 01 8b 45 90 01 01 8b 40 0c 8b 48 0c 66 c7 85 90 01 04 61 00 66 c7 85 90 01 04 79 00 66 c7 85 90 01 04 70 00 8b 41 28 8b d0 83 c2 90 01 01 66 8b 12 66 3b 95 90 01 02 ff ff 75 90 00 } //01 00 
		$a_03_5 = {64 8b 15 30 00 00 00 89 55 90 01 01 8b 45 90 01 01 8b 40 0c 8b 48 0c 66 c7 85 90 01 04 70 00 8b 41 28 8b d0 83 c2 90 01 01 66 8b 12 66 3b 95 90 01 04 75 90 00 } //01 00 
		$a_03_6 = {6d 00 66 c7 45 90 01 01 61 00 66 c7 45 90 01 01 78 00 8b 45 90 01 01 8b 40 28 8b d0 83 c2 06 66 8b 12 66 3b 55 90 01 01 75 1b 8b d0 83 c2 90 01 01 66 8b 12 66 3b 55 90 01 01 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}