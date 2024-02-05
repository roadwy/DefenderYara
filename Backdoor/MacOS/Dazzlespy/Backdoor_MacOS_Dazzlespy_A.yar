
rule Backdoor_MacOS_Dazzlespy_A{
	meta:
		description = "Backdoor:MacOS/Dazzlespy.A,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {38 38 2e 32 31 38 2e 31 39 32 2e 31 32 38 3a 35 36 33 33 } //01 00 
		$a_01_1 = {4b 65 79 63 68 61 69 6e 20 44 61 74 61 3a 20 25 40 } //01 00 
		$a_00_2 = {25 40 2f 2e 6c 6f 63 61 6c 2f 73 6f 66 74 77 61 72 65 75 70 64 61 74 65 } //01 00 
		$a_00_3 = {2f 63 6f 6d 2e 61 70 70 6c 65 2e 73 6f 66 74 77 61 72 65 75 70 64 61 74 65 2e 70 6c 69 73 74 } //01 00 
		$a_00_4 = {2e 6c 6f 63 61 6c 2f 73 65 63 75 72 69 74 79 2f 6b 65 79 73 74 65 61 6c 44 61 65 6d 6f 6e } //00 00 
	condition:
		any of ($a_*)
 
}