
rule Trojan_Win32_Stealc_DZ_MTB{
	meta:
		description = "Trojan:Win32/Stealc.DZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 c5 8d 0c 37 33 c1 89 54 24 18 89 44 24 10 89 1d 90 02 04 8b 44 24 18 01 05 90 02 04 8b 15 90 02 04 89 54 24 38 89 5c 24 18 8b 44 24 38 01 44 24 18 8b 44 24 10 33 44 24 18 89 44 24 18 8b 44 24 18 89 44 24 18 8b 44 24 18 29 44 24 14 8b 4c 24 14 c1 e1 04 89 4c 24 10 8b 44 24 2c 01 44 24 10 81 3d 90 02 04 be 01 00 00 8b 44 24 14 8d 1c 07 75 90 00 } //01 00 
		$a_01_1 = {6b 65 73 6f 7a 75 62 65 78 61 7a 61 78 61 68 69 66 61 68 75 76 75 74 6f 7a 69 74 75 63 65 70 } //00 00  kesozubexazaxahifahuvutozitucep
	condition:
		any of ($a_*)
 
}