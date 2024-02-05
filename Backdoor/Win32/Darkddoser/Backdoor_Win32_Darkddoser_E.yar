
rule Backdoor_Win32_Darkddoser_E{
	meta:
		description = "Backdoor:Win32/Darkddoser.E,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {55 44 50 7c 90 02 19 53 59 4e 7c 90 02 10 48 54 54 50 7c 90 00 } //01 00 
		$a_01_1 = {28 2a 2e 65 78 65 29 7c 2a 2e 65 78 65 7c 63 6f 6d 20 28 2a 2e 63 6f 6d 29 7c 2a 2e 63 6f 6d 7c 70 69 66 20 28 2a 2e 70 69 66 29 7c 2a 2e 70 69 66 } //01 00 
		$a_01_2 = {64 61 72 6b 64 64 6f 73 65 72 } //05 00 
		$a_03_3 = {0f b6 08 2a 0a 75 90 01 01 53 8b 58 fc 2b 5a fc 53 83 d1 ff 21 d9 2b 48 fc 29 c8 29 ca 8b 1c 01 33 1c 11 90 00 } //00 00 
		$a_00_4 = {5d 04 00 00 9f 05 } //03 80 
	condition:
		any of ($a_*)
 
}