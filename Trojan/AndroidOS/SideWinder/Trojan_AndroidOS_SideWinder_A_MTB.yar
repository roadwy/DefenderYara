
rule Trojan_AndroidOS_SideWinder_A_MTB{
	meta:
		description = "Trojan:AndroidOS/SideWinder.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {70 34 64 32 33 36 64 39 61 2f 70 63 33 31 62 33 32 33 36 2f 70 65 61 65 31 38 62 63 34 2f 70 31 30 63 64 33 39 35 63 } //01 00 
		$a_01_1 = {6c 6f 61 64 46 72 6f 6d 44 69 73 6b } //01 00 
		$a_01_2 = {64 6f 77 6e 6c 6f 61 64 65 64 44 61 74 61 } //01 00 
		$a_01_3 = {69 6e 4d 65 6d 6f 72 79 46 69 6c 65 4c 6f 61 64 4d 6f 64 75 6c 65 } //01 00 
		$a_01_4 = {4c 64 61 6c 76 69 6b 2f 73 79 73 74 65 6d 2f 49 6e 4d 65 6d 6f 72 79 44 65 78 43 6c 61 73 73 4c 6f 61 64 65 72 3b } //00 00 
	condition:
		any of ($a_*)
 
}