
rule Backdoor_MacOS_Olyx_C_MTB{
	meta:
		description = "Backdoor:MacOS/Olyx.C!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {6d 61 69 6c 2e 74 62 6e 65 77 73 70 61 70 65 72 2e 63 6f 6d } //01 00 
		$a_00_1 = {63 6f 6d 2e 61 70 70 6c 65 2e 64 6f 63 73 65 72 76 65 72 } //01 00 
		$a_00_2 = {2f 4c 69 62 72 61 72 79 2f 4c 61 75 6e 63 68 41 67 65 6e 74 73 2f 63 6f 6d 2e 61 70 70 6c 65 2e 41 75 64 69 6f 53 65 72 76 69 63 65 2e 70 6c 69 73 74 } //01 00 
		$a_00_3 = {50 6c 75 67 2d 49 6e 73 2f 43 6f 6d 70 6f 6e 65 6e 74 73 2f 41 75 64 69 6f 53 65 72 76 69 63 65 } //00 00 
		$a_00_4 = {5d 04 00 } //00 ed 
	condition:
		any of ($a_*)
 
}