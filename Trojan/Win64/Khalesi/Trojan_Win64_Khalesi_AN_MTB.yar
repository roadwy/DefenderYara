
rule Trojan_Win64_Khalesi_AN_MTB{
	meta:
		description = "Trojan:Win64/Khalesi.AN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 06 00 00 03 00 "
		
	strings :
		$a_00_0 = {59 54 42 53 42 62 4e 54 57 55 } //02 00 
		$a_01_1 = {47 65 74 43 6f 6d 70 75 74 65 72 4e 61 6d 65 41 } //02 00 
		$a_01_2 = {53 77 69 74 63 68 54 6f 46 69 62 65 72 } //02 00 
		$a_01_3 = {44 65 6c 65 74 65 46 69 62 65 72 } //02 00 
		$a_01_4 = {52 65 73 75 6d 65 54 68 72 65 61 64 } //02 00 
		$a_01_5 = {47 65 74 4d 6f 64 75 6c 65 46 69 6c 65 4e 61 6d 65 41 } //00 00 
	condition:
		any of ($a_*)
 
}