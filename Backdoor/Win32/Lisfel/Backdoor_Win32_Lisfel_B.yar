
rule Backdoor_Win32_Lisfel_B{
	meta:
		description = "Backdoor:Win32/Lisfel.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 73 6d 3d 25 73 26 63 74 3d 25 64 26 69 3d 25 73 00 } //01 00 
		$a_01_1 = {25 73 4c 49 53 46 4c 2e 64 6c 6c 00 } //01 00 
		$a_01_2 = {77 6c 63 6d 64 3a 65 78 69 74 00 } //01 00 
		$a_01_3 = {73 67 65 74 20 65 72 72 30 72 21 0a 00 } //00 00 
	condition:
		any of ($a_*)
 
}