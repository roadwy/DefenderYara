
rule PWS_Win32_Maran_M{
	meta:
		description = "PWS:Win32/Maran.M,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {68 00 dd 6d 00 6a 00 6a 00 e8 90 01 04 a3 90 02 08 68 90 01 04 68 10 27 00 00 6a 00 6a 00 e8 90 01 04 a3 90 01 04 eb 0c 90 00 } //01 00 
		$a_00_1 = {76 67 61 64 6f 77 6e 00 } //01 00  杶摡睯n
		$a_00_2 = {76 67 61 64 30 77 6e 00 } //00 00  杶摡眰n
	condition:
		any of ($a_*)
 
}