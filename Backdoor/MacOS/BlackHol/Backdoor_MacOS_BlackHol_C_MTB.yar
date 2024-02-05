
rule Backdoor_MacOS_BlackHol_C_MTB{
	meta:
		description = "Backdoor:MacOS/BlackHol.C!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 75 73 72 2f 73 62 69 6e 2f 73 63 72 65 65 6e 63 61 70 74 75 72 65 20 2d 78 20 2f 41 70 70 6c 69 63 61 74 69 6f 6e 73 2f } //01 00 
		$a_00_1 = {2f 2e 44 61 74 61 2f 61 64 64 2e 61 70 70 2f 43 6f 6e 74 65 6e 74 73 2f 4d 61 63 4f 53 } //01 00 
		$a_00_2 = {2f 2e 44 61 74 61 2f 61 64 64 32 2e 61 70 70 2f 43 6f 6e 74 65 6e 74 73 2f 4d 61 63 4f 53 } //01 00 
		$a_00_3 = {70 68 69 73 68 32 5f 43 6f 6e 6e 65 63 74 65 64 } //01 00 
		$a_00_4 = {50 68 69 73 68 57 69 6e 64 6f 77 2e 50 68 69 73 68 57 69 6e 64 6f 77 } //00 00 
		$a_00_5 = {5d 04 00 } //00 f8 
	condition:
		any of ($a_*)
 
}