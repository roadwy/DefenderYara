
rule Virus_Win32_Sality_H{
	meta:
		description = "Virus:Win32/Sality.H,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {68 00 50 00 00 6a 00 6a 00 6a 02 a1 90 01 02 00 10 50 ff 15 90 01 02 00 10 90 02 20 81 e1 ff 00 00 00 83 f9 02 75 27 8b 15 90 01 02 00 10 33 c0 8a 02 3d 81 00 00 00 74 16 68 00 50 00 00 90 00 } //01 00 
		$a_01_1 = {68 00 10 00 00 68 66 06 00 00 6a 00 ff } //00 00 
	condition:
		any of ($a_*)
 
}