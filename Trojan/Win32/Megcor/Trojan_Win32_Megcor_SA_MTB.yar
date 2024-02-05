
rule Trojan_Win32_Megcor_SA_MTB{
	meta:
		description = "Trojan:Win32/Megcor.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {21 2d 21 5f 52 45 41 44 4d 45 5f 21 2d 21 2e 72 74 66 } //01 00 
		$a_81_1 = {5b 2b 5d 20 73 74 61 72 74 65 64 3a } //01 00 
		$a_81_2 = {2e 63 6d 64 20 25 31 25 20 63 69 70 68 65 72 20 77 6d 69 63 } //01 00 
		$a_81_3 = {5b 2b 5d 20 69 73 53 61 6e 62 6f 78 65 64 } //01 00 
		$a_81_4 = {5b 2b 5d 20 70 72 6f 63 65 73 73 69 6e 67 } //01 00 
		$a_81_5 = {64 65 6c 20 2f 51 20 2f 46 } //01 00 
		$a_81_6 = {65 63 68 6f 20 65 63 68 6f 20 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 20 3e 3e } //00 00 
	condition:
		any of ($a_*)
 
}