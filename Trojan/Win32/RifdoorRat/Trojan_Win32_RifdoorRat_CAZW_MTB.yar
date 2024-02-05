
rule Trojan_Win32_RifdoorRat_CAZW_MTB{
	meta:
		description = "Trojan:Win32/RifdoorRat.CAZW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 77 77 77 2e 68 65 6c 6c 6f 62 65 74 74 61 2e 63 6f 6d 2f 6d 61 6c 6c 2f 66 6c 61 73 68 2f 50 4f 50 55 50 2f 31 2e 70 68 70 } //01 00 
		$a_01_1 = {68 74 74 70 3a 2f 2f 77 77 77 2e 61 65 67 61 2e 63 6f 2e 6b 72 2f 6d 61 6c 6c 2f 6d 61 6e 75 61 6c 2f 70 61 72 73 65 72 2f 70 61 72 73 65 72 2e 70 68 70 } //01 00 
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00 
		$a_01_3 = {44 6f 77 6e 6c 6f 61 64 65 78 65 63 20 73 75 63 63 65 73 73 } //01 00 
		$a_01_4 = {41 68 6e 55 70 61 64 61 74 65 } //00 00 
	condition:
		any of ($a_*)
 
}