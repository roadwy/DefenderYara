
rule Trojan_Win32_Delf_EN_MTB{
	meta:
		description = "Trojan:Win32/Delf.EN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 03 00 "
		
	strings :
		$a_81_0 = {44 4f 4e 47 41 } //03 00 
		$a_81_1 = {49 43 45 58 50 } //03 00 
		$a_81_2 = {42 4d 36 63 00 00 00 00 00 00 76 00 00 00 28 00 00 00 3f 01 00 00 9e 00 00 00 01 } //03 00 
		$a_81_3 = {4f 6e 4b 65 79 50 72 65 73 73 } //03 00 
		$a_81_4 = {47 65 74 4d 6f 6e 69 74 6f 72 49 6e 66 6f 57 } //03 00 
		$a_81_5 = {53 68 65 6c 6c 46 6f 6c 64 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Delf_EN_MTB_2{
	meta:
		description = "Trojan:Win32/Delf.EN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 2e 53 74 6f 6e 65 } //01 00 
		$a_01_1 = {53 74 69 6b 79 4e 6f 74 2e 65 78 65 } //01 00 
		$a_01_2 = {53 79 6e 63 48 6f 73 74 2e 65 78 65 } //01 00 
		$a_01_3 = {53 74 69 6b 79 4e 6f 74 5f 79 61 6b 75 7a 61 } //01 00 
		$a_01_4 = {45 6e 63 72 79 70 74 65 64 20 62 79 20 53 74 6f 6e 65 2f 55 43 46 } //01 00 
		$a_01_5 = {50 6f 77 65 72 4c 61 6d 65 20 50 45 2d 45 78 65 45 6e 43 72 79 70 74 65 72 21 } //00 00 
	condition:
		any of ($a_*)
 
}