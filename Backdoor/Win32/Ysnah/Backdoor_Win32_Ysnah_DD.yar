
rule Backdoor_Win32_Ysnah_DD{
	meta:
		description = "Backdoor:Win32/Ysnah.DD,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 38 2e 30 3b 20 57 69 6e 33 32 29 } //02 00 
		$a_00_1 = {33 37 36 35 2d 34 35 39 31 2d 45 38 44 46 2d 39 39 45 4a } //01 00 
		$a_00_2 = {8d 04 31 8a 1c 07 2a d9 80 eb 0a 41 3b ca 88 18 } //01 00 
		$a_03_3 = {88 5d dd c6 45 90 01 01 30 c6 45 90 01 01 2e c6 45 90 01 01 30 c6 45 90 01 01 2e c6 45 90 01 01 30 c6 45 90 01 01 2e c6 45 90 01 01 30 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}