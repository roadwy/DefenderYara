
rule Worm_Win32_Hikjav_A{
	meta:
		description = "Worm:Win32/Hikjav.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {c6 44 24 10 63 c7 44 24 14 90 01 04 8a 44 24 10 be 90 01 04 8d 7c 24 0c 66 a5 a4 88 44 24 0c 8d 44 24 0c 50 ff d3 83 f8 02 74 21 8d 44 24 0c 50 ff d3 83 f8 03 74 15 90 00 } //01 00 
		$a_01_1 = {25 63 3a 5c 61 75 74 6f 72 75 6e 2e 69 6e 66 } //01 00 
		$a_01_2 = {25 63 3a 5c 52 45 43 59 43 4c 45 52 } //00 00 
	condition:
		any of ($a_*)
 
}