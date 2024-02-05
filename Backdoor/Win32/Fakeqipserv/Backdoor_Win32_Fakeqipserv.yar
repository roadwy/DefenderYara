
rule Backdoor_Win32_Fakeqipserv{
	meta:
		description = "Backdoor:Win32/Fakeqipserv,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 6d 61 72 6b 65 74 69 6e 67 67 2e 6a 69 6e 6f 2d 6e 65 74 2e 72 75 2f 70 72 6f 78 79 2f 67 61 74 65 2e 70 68 70 } //01 00 
		$a_01_1 = {48 54 54 50 50 72 6f 78 79 53 65 72 76 65 72 31 } //01 00 
		$a_01_2 = {57 69 6e 64 6f 77 73 5f 56 69 64 65 6f 00 } //01 00 
		$a_01_3 = {53 65 72 76 69 63 65 54 61 62 6c 65 45 6e 74 72 79 41 72 72 61 79 } //01 00 
		$a_01_4 = {50 72 6f 78 79 50 61 73 73 77 6f 72 64 3c } //00 00 
	condition:
		any of ($a_*)
 
}