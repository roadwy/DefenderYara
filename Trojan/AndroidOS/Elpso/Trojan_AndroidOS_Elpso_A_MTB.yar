
rule Trojan_AndroidOS_Elpso_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Elpso.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {65 63 6c 69 70 73 70 6c 61 79 65 72 2e 63 6f 6d } //01 00 
		$a_00_1 = {76 6f 64 2e 76 6f 64 34 2e 6d 6f 62 69 } //01 00 
		$a_00_2 = {73 65 6e 64 4d 75 6c 74 69 70 61 72 74 54 65 78 74 4d 65 73 73 61 67 65 } //01 00 
		$a_00_3 = {50 61 79 2d 50 65 72 2d 43 6c 69 63 6b 20 6d 6f 64 75 73 } //01 00 
		$a_00_4 = {75 73 65 50 72 69 76 61 74 65 4d 61 69 6c 62 6f 78 } //00 00 
	condition:
		any of ($a_*)
 
}