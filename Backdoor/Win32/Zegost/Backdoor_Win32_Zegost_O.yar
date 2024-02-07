
rule Backdoor_Win32_Zegost_O{
	meta:
		description = "Backdoor:Win32/Zegost.O,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 03 00 "
		
	strings :
		$a_03_0 = {41 c6 44 24 90 01 01 6e c6 44 24 90 01 01 67 c6 44 24 90 01 01 65 90 00 } //01 00 
		$a_00_1 = {5c 4d 79 49 6e 66 6f 72 6d 61 74 69 6f 6e 73 2e 69 6e 69 } //01 00  \MyInformations.ini
		$a_00_2 = {25 73 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 43 6f 6d 6d 6f 6e 20 46 69 6c 65 73 5c 25 63 25 63 25 63 25 63 25 63 25 63 25 63 2e 25 63 25 63 25 63 25 63 25 63 } //01 00  %s:\Program Files\Common Files\%c%c%c%c%c%c%c.%c%c%c%c%c
		$a_00_3 = {25 73 2c 43 6f 64 65 4d 61 69 6e 20 25 73 } //01 00  %s,CodeMain %s
		$a_00_4 = {5c 41 6e 67 65 6c 2e 63 63 00 } //01 00  䅜杮汥挮c
		$a_00_5 = {5c 74 65 6d 70 5c 50 6c 67 75 69 6e 73 2e 74 78 74 00 } //00 00 
	condition:
		any of ($a_*)
 
}