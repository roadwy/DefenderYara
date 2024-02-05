
rule Trojan_Win64_IcedID_MU_MTB{
	meta:
		description = "Trojan:Win64/IcedID.MU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {48 8d 44 3e 10 48 ba 61 61 61 61 61 61 61 61 31 c9 49 89 f0 48 89 10 48 89 50 08 48 89 50 10 48 89 50 18 48 89 50 20 48 89 50 28 48 89 50 30 48 89 50 38 49 63 c7 31 d2 c6 44 04 20 00 c6 44 1c 20 00 ff 15 ea 68 08 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_IcedID_MU_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.MU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {52 75 6e 4f 62 6a 65 63 74 } //01 00 
		$a_01_1 = {51 53 30 37 4a 63 2e 64 6c 6c } //01 00 
		$a_01_2 = {41 48 70 4f 77 4a 77 64 62 } //01 00 
		$a_01_3 = {42 53 4b 4b 58 4b 68 57 41 65 } //01 00 
		$a_01_4 = {44 47 43 6d 6f 4c 52 61 56 68 59 } //01 00 
		$a_01_5 = {57 6e 4f 72 5a 73 61 78 47 41 6e } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_IcedID_MU_MTB_3{
	meta:
		description = "Trojan:Win64/IcedID.MU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {61 63 70 6e 6c 68 62 63 64 78 6e 64 6b } //02 00 
		$a_01_1 = {61 6c 6d 68 71 6e 76 69 64 6d } //02 00 
		$a_01_2 = {62 77 68 74 7a 79 6c 73 7a 6b 78 68 75 65 76 73 } //02 00 
		$a_01_3 = {66 64 70 78 61 65 6d 63 66 65 74 6f 6d 70 70 6d } //01 00 
		$a_01_4 = {53 65 74 46 69 6c 65 41 70 69 73 54 6f 4f 45 4d } //01 00 
		$a_01_5 = {47 65 74 54 69 63 6b 43 6f 75 6e 74 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_IcedID_MU_MTB_4{
	meta:
		description = "Trojan:Win64/IcedID.MU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 63 6d 64 2e 65 78 65 20 2f 63 20 63 5e 75 5e 72 5e 6c 20 2d 6f 20 63 3a 5c 75 73 65 72 73 5c 70 75 62 6c 69 63 5c 90 02 10 2e 6d 73 69 20 68 74 74 70 3a 2f 2f 90 02 15 2f 90 02 10 2f 90 02 10 26 26 74 69 6d 65 6f 75 74 20 31 35 26 26 63 3a 5c 75 73 65 72 73 5c 70 75 62 6c 69 63 5c 90 02 10 2e 6d 73 69 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}