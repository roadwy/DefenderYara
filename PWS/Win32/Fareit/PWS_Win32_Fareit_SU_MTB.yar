
rule PWS_Win32_Fareit_SU_MTB{
	meta:
		description = "PWS:Win32/Fareit.SU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {68 41 41 41 41 90 02 10 83 c6 01 90 02 05 8b 17 90 02 10 31 f2 90 02 10 39 ca 75 90 00 } //01 00 
		$a_03_1 = {b9 00 5f 00 00 90 02 10 49 90 02 10 8b 1c 0f 90 02 10 53 90 02 20 31 34 24 90 02 25 8f 04 08 90 02 15 83 f9 00 7f 90 00 } //00 00 
		$a_00_2 = {5d } //04 00  ]
	condition:
		any of ($a_*)
 
}