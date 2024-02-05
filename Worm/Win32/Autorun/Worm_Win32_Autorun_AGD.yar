
rule Worm_Win32_Autorun_AGD{
	meta:
		description = "Worm:Win32/Autorun.AGD,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {5c 52 45 43 59 43 4c 45 52 00 00 00 2e 3a 3a 5b 55 73 62 5d 3a 3a 2e 20 49 6e 66 65 63 74 65 64 20 64 72 69 76 65 3a 20 25 73 } //01 00 
		$a_01_1 = {5c 61 75 74 6f 72 75 6e 2e 69 6e 66 } //01 00 
		$a_01_2 = {48 4f 53 54 3a 20 77 77 77 2e 61 64 6f 62 65 2e 63 6f 6d 2e 63 6e } //01 00 
		$a_01_3 = {64 65 6c 20 25 25 30 } //00 00 
	condition:
		any of ($a_*)
 
}