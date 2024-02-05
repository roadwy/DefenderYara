
rule Ransom_Win32_Conti_MB_MTB{
	meta:
		description = "Ransom:Win32/Conti.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 04 00 00 0a 00 "
		
	strings :
		$a_03_0 = {69 0a 95 e9 d1 5b 83 c2 90 02 01 69 ff 90 02 04 8b c1 c1 e8 90 02 01 33 c1 69 c8 90 1b 01 33 f9 83 eb 01 75 90 00 } //0a 00 
		$a_01_1 = {65 78 70 61 6e 64 20 33 32 2d 62 79 74 65 20 6b } //0a 00 
		$a_01_2 = {65 78 70 61 6e 64 20 31 36 2d 62 79 74 65 20 6b } //05 00 
		$a_81_3 = {2e 4a 56 55 41 45 } //00 00 
		$a_00_4 = {5d 04 00 00 1a 78 04 80 5c 3a 00 00 1b 78 04 80 00 00 01 00 04 00 24 00 54 72 6f 6a 61 6e } //44 6f 
	condition:
		any of ($a_*)
 
}