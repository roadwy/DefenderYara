
rule Trojan_Win32_Reline_AWC_MTB{
	meta:
		description = "Trojan:Win32/Reline.AWC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {50 61 6e 61 73 6f 6e 69 63 20 45 6e 65 6c 6f 6f 70 20 50 72 6f 20 32 78 41 41 20 32 35 30 30 20 6d 41 68 } //01 00  Panasonic Eneloop Pro 2xAA 2500 mAh
		$a_81_1 = {32 31 30 39 30 38 31 35 30 34 33 37 } //01 00  210908150437
		$a_81_2 = {33 31 30 39 30 39 31 35 30 34 33 37 } //01 00  310909150437
		$a_01_3 = {31 00 2e 00 32 00 2e 00 31 00 35 00 36 00 2e 00 35 00 36 00 33 00 35 00 39 00 } //01 00  1.2.156.56359
		$a_81_4 = {4e 65 77 20 4a 65 72 73 65 79 } //01 00  New Jersey
		$a_81_5 = {47 72 65 61 74 65 72 20 4d 61 6e 63 68 65 73 74 65 72 } //01 00  Greater Manchester
		$a_81_6 = {53 61 6c 66 6f 72 64 } //00 00  Salford
	condition:
		any of ($a_*)
 
}