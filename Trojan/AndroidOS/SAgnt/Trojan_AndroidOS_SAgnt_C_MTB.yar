
rule Trojan_AndroidOS_SAgnt_C_MTB{
	meta:
		description = "Trojan:AndroidOS/SAgnt.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2f 69 73 6a 6b 2f 69 65 69 6b 64 } //01 00 
		$a_00_1 = {63 68 65 63 6b 52 6f 6f 74 50 65 72 6d 69 73 73 69 6f 6e } //01 00 
		$a_01_2 = {43 4f 44 45 5f 42 45 47 41 49 4e 5f 49 4e 53 54 45 4c 4c } //01 00 
		$a_00_3 = {73 75 74 6f 6e 67 6a 69 2e 70 68 70 } //01 00 
		$a_00_4 = {67 65 74 54 6f 70 41 63 74 69 76 69 74 79 50 61 63 6b 61 67 65 4e 61 6d 65 } //00 00 
	condition:
		any of ($a_*)
 
}