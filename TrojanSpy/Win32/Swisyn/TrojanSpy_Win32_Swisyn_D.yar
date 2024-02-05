
rule TrojanSpy_Win32_Swisyn_D{
	meta:
		description = "TrojanSpy:Win32/Swisyn.D,SIGNATURE_TYPE_PEHSTR_EXT,08 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 2e 32 75 2f 25 2e 32 75 2f 25 75 20 25 2e 32 75 3a 25 2e 32 75 } //01 00 
		$a_01_1 = {5b 53 63 68 6f 77 65 6b 5d } //02 00 
		$a_01_2 = {43 3a 5c 49 6e 73 69 64 65 54 6d 5c } //03 00 
		$a_01_3 = {44 3a 5c 70 72 6f 67 72 61 6d 20 7a 20 76 69 73 75 61 6c 61 5c 6b 65 79 6c 6f 67 67 65 72 5c 52 65 6c 65 61 73 65 5c 6b 65 79 6c 6f 67 67 65 72 2e 70 64 62 } //01 00 
		$a_01_4 = {5c 6c 6f 67 2e 74 78 74 } //00 00 
	condition:
		any of ($a_*)
 
}