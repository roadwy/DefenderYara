
rule Trojan_AndroidOS_Plankton_gen_C{
	meta:
		description = "Trojan:AndroidOS/Plankton.gen!C,SIGNATURE_TYPE_DEXHSTR_EXT,0c 00 0b 00 05 00 00 0a 00 "
		
	strings :
		$a_00_0 = {4c 63 6f 6d 2f 70 6c 61 6e 6b 74 6f 6e 2f 64 65 76 69 63 65 2f 61 6e 64 72 6f 69 64 2f 73 65 72 76 69 63 65 2f 41 6e 64 72 6f 69 64 4d 44 4b 53 65 72 76 69 63 65 3b 00 } //01 00 
		$a_00_1 = {4c 63 6f 6d 2f 70 6c 61 6e 6b 74 6f 6e 2f 64 65 76 69 63 65 2f 61 6e 64 72 6f 69 64 2f 73 65 72 76 69 63 65 2f 53 65 6e 64 53 74 61 74 75 73 54 61 73 6b 3b 00 } //01 00 
		$a_00_2 = {70 6c 61 6e 6b 74 6f 6e 5f 75 70 67 72 61 64 65 00 } //01 00 
		$a_00_3 = {2e 63 6f 6d 2f 50 72 6f 74 6f 63 6f 6c 47 57 2f 70 72 6f 74 6f 63 6f 6c 00 } //01 00 
		$a_00_4 = {63 6f 6d 2f 70 6c 61 6e 6b 74 6f 6e 2f 64 65 76 69 63 65 2f 61 6e 64 72 6f 69 64 2f 73 65 72 76 69 63 65 2f 61 3b 00 } //00 00 
	condition:
		any of ($a_*)
 
}