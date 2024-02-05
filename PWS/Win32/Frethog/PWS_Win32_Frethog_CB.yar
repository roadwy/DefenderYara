
rule PWS_Win32_Frethog_CB{
	meta:
		description = "PWS:Win32/Frethog.CB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {71 71 6c 6f 67 69 6e 2e 65 78 65 00 } //01 00 
		$a_00_1 = {25 73 3f 61 63 74 3d 67 65 74 70 6f 73 26 64 31 30 3d 25 73 26 70 6f 73 3d 26 64 38 30 3d 25 64 } //01 00 
		$a_01_2 = {8a 07 c6 07 e9 8b 4f 01 89 4d 10 } //00 00 
	condition:
		any of ($a_*)
 
}