
rule Trojan_AndroidOS_Mania_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Mania.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 61 6c 6b 2f 63 6f 70 69 6c 6f 74 2f 6d 61 72 6b 65 74 70 6c 61 63 65 2f 65 75 2f 66 75 6c 6c } //01 00 
		$a_01_1 = {53 65 6e 64 54 68 65 6d } //01 00 
		$a_01_2 = {67 65 74 4d 65 73 73 61 67 65 42 6f 64 79 } //01 00 
		$a_01_3 = {43 6f 50 69 6c 6f 74 4c 69 76 65 45 75 72 6f 70 65 41 63 74 69 76 69 74 79 } //01 00 
		$a_01_4 = {62 47 6f 6f 64 4e 75 6d 62 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}