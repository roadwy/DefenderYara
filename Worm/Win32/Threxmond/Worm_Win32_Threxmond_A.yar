
rule Worm_Win32_Threxmond_A{
	meta:
		description = "Worm:Win32/Threxmond.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {43 00 3a 00 5c 00 42 00 61 00 73 00 65 00 20 00 64 00 65 00 20 00 64 00 6f 00 6e 00 6e 00 65 00 65 00 5c 00 74 00 65 00 73 00 74 00 5c 00 50 00 72 00 6f 00 6a 00 65 00 74 00 31 00 2e 00 76 00 62 00 70 00 } //03 00  C:\Base de donnee\test\Projet1.vbp
		$a_03_1 = {00 6b 00 3a 00 5c 00 33 00 78 00 58 00 78 00 33 00 90 01 02 2e 00 65 00 78 00 65 00 00 90 00 } //01 00 
		$a_00_2 = {00 00 5b 00 41 00 75 00 74 00 6f 00 72 00 75 00 6e 00 5d 00 00 00 } //01 00 
		$a_01_3 = {66 75 6e 63 6f 70 79 } //00 00  funcopy
	condition:
		any of ($a_*)
 
}