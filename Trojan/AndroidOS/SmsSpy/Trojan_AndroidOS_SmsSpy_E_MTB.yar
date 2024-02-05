
rule Trojan_AndroidOS_SmsSpy_E_MTB{
	meta:
		description = "Trojan:AndroidOS/SmsSpy.E!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_00_0 = {6d 5f 73 6d 73 00 6d 5f 64 61 65 6d 6f 6e 73 65 72 76 69 63 65 00 6d 5f 73 6d 73 73 65 72 76 69 63 65 00 6d 5f 73 79 73 69 6e 66 6f } //01 00 
		$a_00_1 = {73 6d 73 70 74 6c 76 00 76 73 5f 66 69 6c 74 65 72 2e 74 78 74 } //01 00 
		$a_00_2 = {73 2f 62 31 2f 6d 61 69 6e 2f 6d 61 69 6e 2e 64 61 74 } //01 00 
		$a_00_3 = {26 50 68 6f 6e 65 49 6e 66 6f 3d } //00 00 
		$a_00_4 = {be a7 00 } //00 04 
	condition:
		any of ($a_*)
 
}
rule Trojan_AndroidOS_SmsSpy_E_MTB_2{
	meta:
		description = "Trojan:AndroidOS/SmsSpy.E!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {69 6e 74 65 72 6f 70 2f 63 74 62 6f 6b 2e 61 73 70 78 3f 69 64 } //01 00 
		$a_00_1 = {63 6f 6d 2e 73 6f 61 6e 2e 73 6d 73 2e 64 65 6c 69 76 65 72 79 } //01 00 
		$a_00_2 = {67 6d 75 62 65 74 61 2e 67 31 38 38 2e 6e 65 74 2f 53 65 63 75 72 65 50 6f 72 74 61 6c 2f 73 65 72 76 6c 65 74 } //01 00 
		$a_00_3 = {58 44 44 40 3b 2e 2e 37 30 2f 30 35 35 2f 30 38 34 2f 30 37 38 2e 53 5d 59 5e 44 55 42 56 51 53 55 2e 43 5d 43 2e 43 49 5e 53 2f 51 43 40 48 } //01 00 
		$a_00_4 = {41 67 65 6e 63 79 49 44 2e 74 78 74 } //00 00 
	condition:
		any of ($a_*)
 
}