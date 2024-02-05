
rule PWS_Win32_Fareit_N_MTB{
	meta:
		description = "PWS:Win32/Fareit.N!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } //01 00 
		$a_03_1 = {31 34 24 85 90 0a ff 00 ff 37 90 02 ff 31 34 24 90 02 ff 85 d2 90 02 ff 8b 0c 24 90 02 30 01 0c 18 90 02 ff 83 c4 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule PWS_Win32_Fareit_N_MTB_2{
	meta:
		description = "PWS:Win32/Fareit.N!MTB,SIGNATURE_TYPE_PEHSTR,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 51 52 56 57 3d 4d } //01 00 
		$a_01_1 = {50 51 52 56 57 39 } //01 00 
		$a_01_2 = {50 51 52 56 57 3d } //01 00 
		$a_01_3 = {50 51 52 56 57 3d 43 } //01 00 
		$a_01_4 = {50 51 52 56 57 3d 2f } //01 00 
		$a_01_5 = {50 51 52 56 57 3d 6e 31 } //01 00 
		$a_01_6 = {69 6d 61 67 65 68 6c 70 2e 64 6c 6c } //01 00 
		$a_01_7 = {73 68 65 6c 6c 33 32 2e 64 6c 6c } //00 00 
	condition:
		any of ($a_*)
 
}