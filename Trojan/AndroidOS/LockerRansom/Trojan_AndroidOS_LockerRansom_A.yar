
rule Trojan_AndroidOS_LockerRansom_A{
	meta:
		description = "Trojan:AndroidOS/LockerRansom.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {4c 63 6f 6d 2f 6d 79 63 6f 6d 70 61 6e 79 2f 6d 79 61 70 70 2f 4d 79 53 65 72 76 69 63 65 } //01 00 
		$a_00_1 = {4c 63 6f 6d 2f 6d 79 63 6f 6d 70 61 6e 79 2f 6d 79 61 70 70 2f 42 6f 6f 74 52 65 63 65 69 76 65 72 } //01 00 
		$a_00_2 = {4c 61 6e 64 72 6f 69 64 2f 76 69 65 77 2f 57 69 6e 64 6f 77 4d 61 6e 61 67 65 72 24 4c 61 79 6f 75 74 50 61 72 61 6d 73 } //01 00 
		$a_00_3 = {63 6f 6d 2e 61 64 72 74 2e 4c 4f 47 43 41 54 5f 45 4e 54 52 49 45 53 } //00 00 
	condition:
		any of ($a_*)
 
}