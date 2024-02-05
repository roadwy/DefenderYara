
rule PWS_Win32_Chedap_A{
	meta:
		description = "PWS:Win32/Chedap.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {10 0a 8a 1a 98 69 9f 55 } //01 00 
		$a_01_1 = {25 73 3f 61 63 74 3d 61 64 64 26 75 73 65 72 3d 25 73 26 70 77 64 3d 25 73 26 6c 6c 31 3d 25 73 26 6c 6c 32 3d 25 64 26 6c 6c 33 3d 25 73 } //01 00 
		$a_01_2 = {36 35 39 30 34 33 32 31 } //00 00 
	condition:
		any of ($a_*)
 
}