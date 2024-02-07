
rule Backdoor_Linux_Imuler_D{
	meta:
		description = "Backdoor:Linux/Imuler.D,SIGNATURE_TYPE_MACHOHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 74 6d 70 2f 6c 61 75 6e 63 68 2d 49 } //01 00  /tmp/launch-I
		$a_01_1 = {2f 62 69 6e 2f 73 68 } //01 00  /bin/sh
		$a_01_2 = {2e 63 6f 6e 66 72 } //02 00  .confr
		$a_03_3 = {46 49 4c 45 90 02 05 41 47 45 4e 90 02 05 54 56 65 72 90 00 } //02 00 
		$a_01_4 = {80 3a 2f 75 0a 83 f9 04 74 0b c6 42 01 00 41 48 4a 85 c0 } //02 00 
		$a_01_5 = {2f 80 00 2f 40 9e 00 14 2f 89 00 04 41 9e 00 14 99 62 00 01 39 29 00 01 } //00 00 
		$a_00_6 = {5d 04 00 00 } //73 d0 
	condition:
		any of ($a_*)
 
}