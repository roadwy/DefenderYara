
rule Virus_Win32_Expiro_CCCF_MTB{
	meta:
		description = "Virus:Win32/Expiro.CCCF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 54 50 57 51 ff d2 } //01 00 
		$a_03_1 = {42 8d 13 8b 12 85 f9 81 f2 90 01 04 3b da 4a 89 17 29 ca 83 e9 04 83 c7 04 83 c3 04 85 c9 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}