
rule Backdoor_Win32_ScarCruft_A_dha{
	meta:
		description = "Backdoor:Win32/ScarCruft.A!dha,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 54 65 6e 63 65 6e 74 5c 51 51 50 43 4d 67 72 } //01 00 
		$a_01_1 = {6f 70 65 6e 66 61 69 6c 00 } //01 00 
		$a_01_2 = {6d 65 6d 66 61 69 6c 00 } //01 00 
		$a_01_3 = {61 6c 6c 6f 63 66 61 69 6c 00 } //01 00 
		$a_01_4 = {53 55 43 43 00 } //01 00 
		$a_01_5 = {46 61 69 6c 00 } //00 00 
	condition:
		any of ($a_*)
 
}