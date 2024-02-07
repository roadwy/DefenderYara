
rule Ransom_Win32_LockScreen_DN{
	meta:
		description = "Ransom:Win32/LockScreen.DN,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {75 6e 6c 6f 63 6b 5f 73 79 73 74 65 6d 00 } //01 00  湵潬正獟獹整m
		$a_01_1 = {4b 69 6c 6c 45 78 70 6c 6f 72 65 72 00 } //01 00 
		$a_01_2 = {44 69 73 61 62 6c 65 52 65 67 65 64 69 74 00 } //01 00 
		$a_01_3 = {4c 6f 63 6b 53 79 73 74 65 6d 00 } //01 00 
		$a_01_4 = {57 49 4e 4c 4f 43 4b } //01 00  WINLOCK
		$a_01_5 = {77 00 69 00 6e 00 6c 00 6f 00 63 00 6b 00 66 00 69 00 6c 00 65 00 2e 00 65 00 78 00 65 00 00 00 } //00 00 
		$a_00_6 = {5d 04 00 00 } //b5 42 
	condition:
		any of ($a_*)
 
}