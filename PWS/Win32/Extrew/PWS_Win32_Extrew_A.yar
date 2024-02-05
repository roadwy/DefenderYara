
rule PWS_Win32_Extrew_A{
	meta:
		description = "PWS:Win32/Extrew.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {66 c7 44 24 90 01 01 d4 07 66 c7 44 24 90 01 01 08 00 66 c7 44 24 90 01 01 11 00 66 c7 44 24 90 01 01 14 00 90 00 } //01 00 
		$a_01_1 = {68 22 3d 01 00 ff d0 83 c4 08 3d 22 3d 01 00 7c 26 } //01 00 
		$a_00_2 = {25 73 5c 25 64 2e 57 57 57 00 } //00 00 
	condition:
		any of ($a_*)
 
}