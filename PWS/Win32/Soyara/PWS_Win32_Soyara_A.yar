
rule PWS_Win32_Soyara_A{
	meta:
		description = "PWS:Win32/Soyara.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 6f 72 61 79 61 56 } //01 00 
		$a_01_1 = {6d 6f 64 65 3d 35 26 63 6f 6d 70 69 6e 66 6f 3d } //01 00 
		$a_03_2 = {76 77 65 62 00 90 02 10 76 73 74 65 61 6c 74 68 00 90 00 } //01 00 
		$a_01_3 = {50 4f 53 4d 61 69 6e 4d 75 74 65 78 } //01 00 
		$a_03_4 = {54 72 61 63 6b 20 90 02 10 26 74 72 61 63 6b 3d 90 00 } //01 00 
		$a_01_5 = {0f b6 d9 03 5d fc 8a 08 d3 c3 40 8a 08 89 5d fc 84 c9 75 ec } //00 00 
	condition:
		any of ($a_*)
 
}