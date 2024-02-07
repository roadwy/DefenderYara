
rule Ransom_MSIL_SaylesCrypt_PA_MTB{
	meta:
		description = "Ransom:MSIL/SaylesCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {59 00 6f 00 75 00 72 00 20 00 63 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 20 00 68 00 61 00 73 00 20 00 62 00 65 00 65 00 6e 00 20 00 69 00 6e 00 66 00 65 00 63 00 74 00 65 00 64 00 20 00 62 00 79 00 20 00 53 00 61 00 79 00 4c 00 65 00 73 00 73 00 2d 00 52 00 61 00 6e 00 73 00 6f 00 6d 00 77 00 61 00 72 00 65 00 } //01 00  Your computer has been infected by SayLess-Ransomware
		$a_01_1 = {53 00 41 00 56 00 45 00 20 00 43 00 4f 00 4d 00 50 00 55 00 54 00 45 00 52 00 } //01 00  SAVE COMPUTER
		$a_01_2 = {68 00 61 00 68 00 61 00 5f 00 50 00 4b 00 2e 00 36 00 36 00 36 00 2d 00 4e 00 4b 00 2d 00 4e 00 30 00 72 00 6d 00 c2 00 a1 00 45 00 } //01 00 
		$a_01_3 = {5c 53 61 79 4c 65 73 73 52 6e 6d 20 57 69 6e 64 6f 77 2e 70 64 62 } //00 00  \SayLessRnm Window.pdb
	condition:
		any of ($a_*)
 
}