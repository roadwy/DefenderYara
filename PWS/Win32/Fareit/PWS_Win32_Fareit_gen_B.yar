
rule PWS_Win32_Fareit_gen_B{
	meta:
		description = "PWS:Win32/Fareit.gen!B,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {46 3a 5c 68 56 6a 6a 6d 73 63 6b 5c 7a 75 6e 7a 4d 6f 5c 64 41 51 51 2e 70 64 62 00 } //01 00 
		$a_01_1 = {30 00 78 00 37 00 38 00 33 00 37 00 38 00 34 00 00 00 } //01 00 
		$a_01_2 = {44 00 3a 00 5c 00 44 00 4b 00 4a 00 4b 00 4a 00 5c 00 2e 00 5c 00 44 00 4b 00 4a 00 4b 00 4a 00 53 00 5c 00 2e 00 2e 00 5c 00 4b 00 44 00 4a 00 4b 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}