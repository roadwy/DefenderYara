
rule Backdoor_Win32_Drixed_D{
	meta:
		description = "Backdoor:Win32/Drixed.D,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {68 82 00 00 00 e8 90 01 04 59 6a 40 68 00 30 00 00 68 60 28 00 00 53 ff d0 90 00 } //01 00 
		$a_03_1 = {c9 c3 6a 36 e8 90 01 04 59 ff e0 6a 2b e8 90 01 04 59 ff e0 90 00 } //01 00 
		$a_03_2 = {68 00 28 00 00 57 e8 90 01 04 6a 36 e8 90 01 04 83 c4 0c 68 86 00 00 00 89 85 90 01 02 ff ff e8 90 01 04 59 6a 76 89 85 90 01 02 ff ff e8 90 00 } //00 00 
		$a_00_3 = {78 79 } //00 00  xy
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_Drixed_D_2{
	meta:
		description = "Backdoor:Win32/Drixed.D,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {68 83 00 00 00 e8 90 01 04 59 6a 40 68 00 30 00 00 68 60 28 00 00 53 ff d0 90 00 } //01 00 
		$a_03_1 = {c9 c3 6a 37 e8 90 01 04 59 ff e0 6a 2c e8 90 01 04 59 ff e0 90 00 } //01 00 
		$a_03_2 = {68 00 28 00 00 57 e8 90 01 04 6a 37 e8 90 01 04 83 c4 0c 68 87 00 00 00 89 85 90 01 02 ff ff e8 90 01 04 59 6a 77 89 85 90 01 01 ff ff ff e8 90 00 } //00 00 
		$a_00_3 = {80 10 } //00 00 
	condition:
		any of ($a_*)
 
}