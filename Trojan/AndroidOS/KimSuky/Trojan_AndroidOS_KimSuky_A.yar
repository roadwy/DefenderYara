
rule Trojan_AndroidOS_KimSuky_A{
	meta:
		description = "Trojan:AndroidOS/KimSuky.A,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {4c 63 6f 6d 2f 6b 69 73 61 2f 6d 6f 62 69 6c 65 5f 73 65 63 75 72 69 74 79 } //02 00 
		$a_01_1 = {34 64 33 35 33 37 63 34 32 38 66 34 39 36 39 36 62 37 38 62 31 31 35 61 38 63 32 38 37 37 62 38 36 33 33 32 36 34 64 34 } //02 00 
		$a_01_2 = {53 6f 6d 65 20 70 65 72 6d 69 73 73 69 6f 6e 73 20 61 72 65 20 64 65 6e 69 65 64 2e 20 54 68 65 20 61 70 70 20 6d 61 79 20 6e 6f 74 20 77 6f 72 6b 20 63 6f 72 72 65 63 74 6c 79 } //00 00 
	condition:
		any of ($a_*)
 
}