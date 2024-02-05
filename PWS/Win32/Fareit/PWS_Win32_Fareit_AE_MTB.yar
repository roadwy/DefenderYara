
rule PWS_Win32_Fareit_AE_MTB{
	meta:
		description = "PWS:Win32/Fareit.AE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f 6e fe 85 90 02 15 90 18 0f 6e da 90 02 15 31 f2 90 02 15 c3 90 00 } //01 00 
		$a_03_1 = {0f 6e fe 83 90 02 15 90 18 0f 6e da 90 02 15 31 f2 90 02 15 c3 90 00 } //01 00 
		$a_03_2 = {0f 6e fe 3d 90 02 15 90 18 0f 6e da 90 02 15 31 f2 90 02 15 c3 90 00 } //01 00 
		$a_03_3 = {0f 6e fe 81 90 02 15 90 18 0f 6e da 90 02 15 31 f2 90 02 15 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}